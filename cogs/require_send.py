# Free RT - Require Send

from typing import TYPE_CHECKING, Union, Tuple, Dict, List

from discord.ext import commands, tasks
import discord

from asyncio import Event
from time import time

if TYPE_CHECKING:
    from aiomysql import Pool, Cursor
    from util import Backend


MAX_TIMEOUT = 4320


class DataManager:

    TABLES = ("RequireSend", "RequireSendQueue")
    MAX_CHANNELS = 5

    def __init__(self, bot: "Backend"):
        self.bot = bot
        self.ready = Event()
        self.pool: "Pool" = self.bot.mysql.pool
        self.bot.loop.create_task(self._prepare_table())

    async def _prepare_table(self):
        # クラスのインスタンス化時に自動で実行される関数です。
        # テーブルの準備をする。
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"""CREATE TABLE IF NOT EXISTS {self.TABLES[0]} (
                        GuildID BIGINT, ChannelID BIGINT PRIMARY KEY NOT NULL,
                        Timeout FLOAT
                    );"""
                )
                await cursor.execute(
                    f"""CREATE TABLE IF NOT EXISTS {self.TABLES[1]} (
                        GuildID BIGINT, ChannelID BIGINT, UserID BIGINT
                    );"""
                )
                await self._update_cache(cursor)
        self.ready.set()

    async def _update_cache(self, cursor):
        await cursor.execute(f"SELECT * FROM {self.TABLES[0]};")
        for row in await cursor.fetchall():
            if row:
                if row[0] not in self.cache:
                    self.cache[row[0]] = []
                self.cache[row[0]].append(row[1])

    async def write(self, guild_id: int, channel_id: int, timeout: int) -> None:
        "送信必須チャンネルを追加します。"
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"SELECT * FROM {self.TABLES[0]} WHERE GuildID = %s;",
                    (guild_id,)
                )
                assert len(
                    [row for row in await cursor.fetchall()
                     if row[1] != channel_id]
                ) <= self.MAX_CHANNELS, "追加しすぎです。"
                await cursor.execute(
                    f"""INSERT INTO {self.TABLES[0]} VALUES (%s, %s, %s)
                        ON DUPLICATE KEY UPDATE Timeout = %s;""",
                    (guild_id, channel_id, timeout, timeout)
                )
                await self._update_cache(cursor)

    async def delete(self, guild_id: int, channel_id: int) -> None:
        "送信必須チャンネルを削除します。"
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"SELECT * FROM {self.TABLES[0]} WHERE ChannelID = %s;",
                    (channel_id,)
                )
                assert await cursor.fetchone(), "その設定はありません。"
                await cursor.execute(
                    f"DELETE FROM {self.TABLES[0]} WHERE ChannelID = %s;",
                    (channel_id,)
                )
                # もしキューが存在するのならそれも削除しておく。
                await cursor.execute(
                    f"SELECT * FROM {self.TABLES[1]} WHERE ChannelID = %s;",
                    (channel_id,)
                )
                if await cursor.fetchone():
                    await cursor.execute(
                        f"DELETE FROM {self.TABLES[1]} WHERE ChannelID = %s;",
                        (channel_id,)
                    )
                await self._update_cache(cursor)

    async def reads(self, guild_id: int) -> List[Tuple[int, float]]:
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"SELECT ChannelID, Timeout FROM {self.TABLES[0]} WHERE GuildID = %s;",
                    (guild_id,)
                )
                return [row for row in await cursor.fetchall() if row]

    async def add_queue(
        self, cursor: "Cursor", guild_id: int, channel_id: int, user_id: int
    ) -> None:
        "キューに追加します。"
        await cursor.execute(
            f"""SELECT * FROM {self.TABLES[1]}
                WHERE GuildID = %s AND ChannelID = %s AND UserID = %s;""",
            (guild_id, channel_id, user_id)
        )
        if not await cursor.fetchone():
            await cursor.execute(
                f"INSERT INTO {self.TABLES[1]} VALUES (%s, %s, %s);",
                (guild_id, channel_id, user_id)
            )

    async def process_check(self, message: discord.Message) -> None:
        "渡されたメッセージから参加者がキューにいるならもう入力必須に送信したと追加したりします。"
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"SELECT * FROM {self.TABLES[0]} WHERE ChannelID = %s;",
                    (message.channel.id,)
                )
                if await cursor.fetchone():
                    await cursor.execute(
                        f"SELECT * FROM {self.TABLES[1]} WHERE GuildID = %s AND UserID = %s;",
                        (message.guild.id, message.author.id)
                    )
                    if await cursor.fetchone():
                        await self.add_queue(
                            cursor, message.guild.id,
                            message.channel.id, message.author.id
                        )

    async def _remove_queue(self, cursor, guild_id, channel_id, user_id):
        await cursor.execute(
            f"""DELETE FROM {self.TABLES[1]}
                WHERE ChannelID = %s AND UserID = %s;""",
            (channel_id, user_id)
        )
        await cursor.execute(
            f"SELECT * FROM {self.TABLES[1]} WHERE GuildID = %s AND UserID = %s;",
            (guild_id, user_id)
        )
        if len(await cursor.fetchall()) <= 1:
            await self._remove_queue_guild(cursor, guild_id, user_id)

    async def _remove_queue_guild(self, cursor, guild_id, user_id):
        await cursor.execute(
            f"DELETE FROM {self.TABLES[1]} WHERE GuildID = %s AND UserID = %s;",
            (guild_id, user_id)
        )

    async def clean_queue(self) -> None:
        "キューをお掃除します。"
        await self.ready.wait()
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"SELECT * FROM {self.TABLES[1]};"
                )
                # キューを整理して辞書にする。
                queues = {}
                for row in await cursor.fetchall():
                    if (guild := self.bot.get_guild(row[0])):
                        if guild not in queues:
                            queues[guild] = {}
                        if row[2] not in queues[guild]:
                            queues[guild][row[2]] = []
                        queues[guild][row[2]].append(row[1])
                    else:
                        # サーバーが見つからないのならキューを削除しておく。
                        await cursor.execute(
                            f"DELETE FROM {self.TABLES[1]} WHERE GuildID = %s;",
                            (row[0],)
                        )
                # キューにあるユーザーでタイムアウトしているユーザーはキックする。
                now = time()
                for guild in queues:
                    await cursor.execute(
                        f"SELECT * FROM {self.TABLES[0]} WHERE GuildID = %s;",
                        (guild.id,)
                    )
                    for row in await cursor.fetchall():
                        for user_id in queues[guild]:
                            if (member := guild.get_member(user_id)):
                                for channel_id in queues[guild][user_id]:
                                    if channel_id == row[1]:
                                        # もし入力し終わっているなら削除キューに追加する。
                                        await self._remove_queue(
                                            cursor, guild.id, channel_id, user_id
                                        )
                                        break
                                else:
                                    # もしまだ何も送信していないチャンネルがあるならタイムアウトしていないか確かめる。
                                    if now - member.joined_at.timestamp() > row[2]:
                                        # タイムアウトしているならキックを行う。
                                        if queues[guild][user_id]:
                                            # そしてもしキューに何か存在するならキューを全て削除する。
                                            await self._remove_queue_guild(
                                                cursor, guild.id, user_id
                                            )
                                        await member.kick(
                                            reason="入力必須チャンネルを入力せずに放置したため。"
                                        )
                            else:
                                # メンバーがいないなら問答無用でキューのデータを削除する。
                                await self._remove_queue_guild(cursor, guild.id, user_id)
                del queues


class RequireSend(commands.Cog, DataManager):
    def __init__(self, bot: "Backend"):
        self.bot = bot
        self.cache: Dict[int, List[int]] = {}
        super(commands.Cog, self).__init__(self.bot)
        self.process_queue.start()

    @tasks.loop(seconds=30)
    async def process_queue(self):
        # キューにあるユーザーのキックや削除を行うループです。
        await self.clean_queue()

    def cog_unload(self):
        self.process_queue.cancel()

    @commands.group(
        aliases=["rs", "入力必須"], extras={
            "headding": {
                "ja": "参加後に入力しないとキックされるチャンネルの設定",
                "en": "Set up a channel that will kick you if you don't enter it after joining."
            }, "parent": "ServerUseful"
        }
    )
    async def requiresend(self, ctx):
        """!lang ja
        --------
        参加後に指定した時間が経過するまでに何かしら送信しておかないとキックされるチャンネルを設定する機能です。

        Notes
        -----
        最大5個のチャンネルに設定することができます。  
        自己紹介を入力しない人をキックしたい場合などにこの機能は使えます。

        Aliases
        -------
        rs, 入力必須

        !lang en
        --------
        This function allows you to set up a channel that will kick you if you don't send something before a specified amount of time has passed after joining.

        Notes
        -----
        You can set up to five channels.  
        This function can be used when you want to kick people who do not enter their self-introduction.

        Aliases
        -------
        rs"""
        if not ctx.invoked_subcommand:
            await ctx.reply(
                {"ja": "使用方法が違います。",
                 "en": "It is wrong way to use this command."}
            )

    @requiresend.command(aliases=["a", "追加"])
    async def add(
        self, ctx: commands.Context, timeout: float, *,
        channel: Union[discord.TextChannel, discord.Object] = None
    ):
        """!lang ja
        --------
        入力必須チャンネルを追加します。

        Parameters
        ----------
        timeout : float
            何分以内に入力しなければならないかです。  
            サーバーに参加した人がこれに設定した時間が経つまでに指定したチャンネルに何も送信しなかったらキックされます。  
            3日＝4320分以上に設定することはできません。
        channel : テキストチャンネルの名前かメンションまたはID, optinoal
            入力必須とするチャンネルです。  
            もしこの引数を入力しなかった場合はコマンドを実行したチャンネルが代わりに設定されます。

        Aliases
        -------
        a, 追加

        !lang en
        --------
        Adds a required input channel.

        Parameters
        ----------
        timeout : float
            This is the number of minutes the input must be received.  
            If no one who joins the server sends anything to the specified channel for the amount of time set here, it will be kicked.  
            Max is 4320.
        channel : Name, Mention or ID of the text channel, optinoal
            This is the channel to which the target input is required.  
            If this argument is not entered, the channel where the command was executed will be set instead.

        Aliases
        -------
        a"""
        await ctx.typing()
        if timeout <= MAX_TIMEOUT:
            try:
                await self.write(ctx.guild.id, (channel or ctx.channel).id, 60 * timeout)
            except AssertionError:
                await ctx.reply(
                    {"ja": "これ以上追加できません。",
                     "en": "No more can be added."}
                )
            else:
                await ctx.reply("Ok")
        else:
            await ctx.repy(
                {"ja": "一時間以上に設定することはできません。",
                 "en": "It cannot be set to more than one hour."}
            )

    @requiresend.command(aliases=["rm", "削除"])
    async def remove(
        self, ctx, channel: Union[discord.TextChannel, discord.Object] = None
    ):
        """!lang ja
        --------
        入力必須チャンネルを削除します。

        Parameters
        ----------
        channel : テキストチャンネルの名前かメンションまたはID, optional
            入力必須を解除したいチャンネルです。

        Aliases
        -------
        rm, 削除

        !lang en
        --------
        Deletes the required input channels.

        Parameters
        ----------
        channel : text channel name, mention or ID, optional
            This is the channel you want to remove from the input required channel.

        Aliases
        -------
        rm"""
        await ctx.typing()
        try:
            await self.delete(ctx.guild.id, (channel or ctx.channel).id)
        except AssertionError:
            await ctx.reply(
                {"ja": "そのチャンネルは設定されていません。",
                 "en": "The channel is not set."}
            )
        else:
            await ctx.reply("Ok")

    @requiresend.command("list", aliases=["l", "一覧"])
    async def list_(self, ctx):
        """!lang ja
        --------
        設定している入力必須チャンネルのリストを表示します。

        Aliases
        -------
        l, 一覧

        !lang en
        --------
        Displays a list of the input required channels that have been set.

        Aliases
        -------
        l"""
        await ctx.reply(
            embed=discord.Embed(
                title="Require Send",
                description="\n".join(
                    f"<#{row[0]}>：{row[1] / 60}分"
                    for row in await self.reads(ctx.guild.id)
                ), color=self.bot.colors["normal"]
            )
        )

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member):
        if not member.bot:
            if await self.reads(member.guild.id):
                # キックするかもしれないキューに追加する。
                async with self.pool.acquire() as conn:
                    async with conn.cursor() as cursor:
                        await self.add_queue(cursor, member.guild.id, 0, member.id)

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if message.guild and message.channel.id in self.cache.get(message.guild.id, ()):
            await self.process_check(message)


async def setup(bot):
    await bot.add_cog(RequireSend(bot))
