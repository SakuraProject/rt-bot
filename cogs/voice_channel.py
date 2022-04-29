# Free RT - Voice Channel

from typing import TYPE_CHECKING, Union, Literal, Tuple, Dict, List

from discord.ext import commands, tasks
import discord

from time import time

if TYPE_CHECKING:
    from util import Backend
    from aiomysql import Pool


DEFAULT_COOLDOWN = 180


class DataManager:

    TABLES = ("VCChannel", "VCChannelAuthors")

    def __init__(self, cog: "VCChannel"):
        self.cog = cog
        self.pool: "Pool" = self.cog.bot.mysql.pool
        self.cog.bot.loop.create_task(self.init_table())

    async def init_table(self) -> None:
        "テーブルを準備します。インスタンス化した際に自動で実行されます。"
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"""CREATE TABLE IF NOT EXISTS {self.TABLES[0]} (
                        GuildID BIGINT, ChannelID BIGINT, Mode TEXT,
                        Role BIGINT, Template TEXT
                    );"""
                )
                await cursor.execute(
                    f"""CREATE TABLE IF NOT EXISTS {self.TABLES[1]} (
                        ChannelID BIGINT, Mode TEXT, Author BIGINT, Time FLOAT
                    );"""
                )

    async def write(
        self, guild_id: int, channel_id: int, mode: str,
        role_id: int, template: str
    ) -> None:
        "設定を書き込みます。"
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"SELECT ChannelID FROM {self.TABLES[0]} WHERE GuildID = %s;",
                    (guild_id,)
                )
                assert len(await cursor.fetchall()) <= 50, "50より多く設定することはできません。"
                await cursor.execute(
                    f"""SELECT ChannelID FROM {self.TABLES[0]}
                        WHERE ChannelID = %s AND Mode = %s;""",
                    (channel_id, mode)
                )
                if await cursor.fetchone():
                    await cursor.execute(
                        f"""UPDATE {self.TABLES[0]} SET Role = %s, Template = %s
                        WHERE GuildID = %s AND ChannelID = %s AND Mode = %s;""",
                        (role_id, template, guild_id, channel_id, mode)
                    )
                else:
                    await cursor.execute(
                        f"""INSERT INTO {self.TABLES[0]} VALUES (%s, %s, %s, %s, %s);""",
                        (guild_id, channel_id, mode, role_id, template)
                    )

    async def read(
        self, channel_id: int
    ) -> List[Tuple[Literal["tc", "vc"], int, str]]:
        "設定を読み込みます。"
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"""SELECT Mode, Role, Template FROM {self.TABLES[0]}
                        WHERE ChannelID = %s;""", (channel_id,)
                )
                return [
                    (row[0], row[1], row[2])
                    for row in await cursor.fetchall() if row
                ]

    async def delete(self, channel_id: int, mode: str) -> None:
        "設定を削除します。"
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"SELECT ChannelID FROM {self.TABLES[0]} WHERE ChannelID = %s AND Mode = %s;",
                    (channel_id, mode)
                )
                assert await cursor.fetchone(), "その設定が見つかりませんでした。"
                await cursor.execute(
                    f"DELETE FROM {self.TABLES[0]} WHERE ChannelID = %s AND Mode = %s;",
                    (channel_id, mode)
                )

    async def _exists(self, cursor, mode, author):
        await cursor.execute(
            f"SELECT * FROM {self.TABLES[1]} WHERE Mode = %s AND Author = %s;",
            (mode, author)
        )
        return await cursor.fetchone()

    async def add_created(
        self, channel_id: int, mode: Literal["tc", "vc"], author: int
    ) -> None:
        "作ったチャンネルの情報を追加します。"
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                assert not await self._exists(cursor, mode, author), "既に作っているのでもう追加できません。"
                await cursor.execute(
                    f"INSERT INTO {self.TABLES[1]} VALUES (%s, %s, %s, %s);",
                    (channel_id, mode, author, time())
                )

    async def remove_created(
        self, category: discord.CategoryChannel,
        mode: Literal["tc", "vc"], author: int
    ) -> None:
        "作ったチャンネルを削除します。"
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                assert (row := await self._exists(cursor, mode, author)), "そのデータはありません。"
                if (channel := category.guild.get_channel(row[0])):
                    await channel.delete()
                await cursor.execute(
                    f"DELETE FROM {self.TABLES[1]} WHERE Mode = %s AND Author = %s;",
                    (mode, author)
                )


class VCChannel(commands.Cog, DataManager):
    def __init__(self, bot):
        self.bot: "Backend" = bot
        self.cache: Dict[str, float] = {}
        self.cache_delete.start()
        super(commands.Cog, self).__init__(self)

    @tasks.loop(seconds=30)
    async def cache_delete(self):
        # クールダウンのために保存したキャッシュを削除するループです。
        now = time()
        for key, value in list(self.cache.items()):
            if value < now:
                del self.cache[key]

    def cog_unload(self):
        self.cache_delete.cancel()

    @commands.command(
        aliases=["vcチャンネル", "ボイスチャンネル"], extras={
            "headding": {
                "ja": "ボイスチャンネル接続後作成するチャンネル",
                "en": "Channel to be created after voice channel connection."
            }, "parent": "ServerTool"
        }
    )
    async def vcc(
        self, ctx: commands.Context,
        channel: Union[
            discord.VoiceChannel, discord.StageChannel, discord.Object
        ], mode: Literal["tc", "vc"],
        role: Union[discord.Role, Literal["null"]] = "null", *,
        template: Union[bool, str] = "!name!'s channel"
    ):
        """!lang ja
        --------
        ボイスチャンネルチャンネルです。  
        設定したボイスチャンネルに誰かが接続した際にその接続した人用のチャンネルを作成します。  
        作成するチャンネルの名前や見れる役職もカスタムが可能です。

        Parameters
        ----------
        channel : ボイスチャンネルの名前またはメンションまたはID
            接続した際にチャンネルを作成する対象のチャンネルです。
        mode : tc または vc
            `tc`にした場合はテキストチャンネルで`vc`の場合はボイスチャンネルを作成します。
        role : 役職のメンションまたは名前, optional
            作成したチャンネルを持っていないと見れない役職です。  
            指定しない場合は誰でも見れるチャンネルとなります。  
            指定しない場合は`null`を入れてください。
        template : str, default `!name! channel`
            チャンネル名のテンプレートです。  
            チャンネル作成時にこのテンプレートを名前に使います。  
            テンプレートに`!id!`を入れると作成者のIDそして`!name!`を入れると作成者の名前に置き換わります。

        Notes
        -----
        もし設定を削除したいのなら引数の`template`を`off`にしてください。

        Aliases
        -------
        vcチャンネル, ボイスチャンネル

        !lang en
        --------
        Voice Channel Channel
        When someone connects to the voice channel you set up, it will create a channel for that person.  
        The name of the created channel and the positions that can be viewed can be customized.

        Parameters
        ----------
        channel : Name, Mention, or ID of the voice channel
            This is the channel that will be created when you connect to it.
        mode : tc or vc
            If set to `tc`, a text channel will be created, if `vc`, a voice channel will be created.
        role : Mention or name of the role, optional
            This is a role that can only be seen if you have the channel you created.  
            If not specified, the channel will be available to everyone.  
            If you don't specify it, put `null`.
        template : str, default `!name! channel`.
            The template for the channel name.  
            Use this template as the name when creating a channel.  
            If you put `!id!` in the template, it will be replaced by the ID of the creator, and if you put `!name!` in the template, it will be replaced by the name of the creator.

        Notes
        -----
        If you want to remove the configuration, set the `template` argument to `off`.  
        There is a fifteen-second cooldown for channel creation."""
        await ctx.trigger_typing()
        if isinstance(template, bool) and not template:
            try:
                await self.delete(channel.id, mode)
            except AssertionError:
                await ctx.reply(
                    {"ja": f"<#{channel.id}>は設定されていません。",
                     "en": f"<#{channel.id}> is not set."}
                )
            else:
                await ctx.reply(
                    {"ja": "VCチャンネルの設定を削除しました。",
                     "en": "Removed setting the vc channel."}
                )
        else:
            await self.write(
                ctx.guild.id, channel.id, mode,
                role.id if role != "null" else 0, template
            )
            await ctx.reply(
                {"ja": f"vcチャンネルとして<#{channel.id}>を設定しました。",
                 "en": f"I set <#{channel.id}> as VC Channel."}
            )

    async def on_update(
        self, member: discord.Member, vc: discord.VoiceChannel
    ) -> None:
        if not vc:
            return

        for row in await self.read(vc.id):
            try:
                # チャンネルを削除を試みる。
                await self.remove_created(vc.category, row[0], member.id)
            except AssertionError:
                # 削除に失敗したならチャンネルを作成する。
                # チャンネル作成の前にクールダウン用のキャッシュを書き込んでおく。
                # もしクールダウンが必要ならクールダウンが必要と送る。
                now = time()
                if now - self.cache.get(
                    key := f"{vc.id}-{member.id}", now - DEFAULT_COOLDOWN
                ) >= DEFAULT_COOLDOWN:
                    self.cache[key] = time() + DEFAULT_COOLDOWN
                else:
                    return await member.send(
                        {"ja": f"クールダウン中なので`{self.cache[key] - now}`秒待ってください。",
                         "en": f"It's taking cooldown. Please wait until `{self.cache[key] - now}` seconds."}
                    )
                # チャンネルを作成する。
                channel = await getattr(
                    vc.category,
                    f"create_{'voice' if row[0] == 'vc' else 'text'}_channel"
                )(
                    name=row[2].replace("!name!", member.name).replace("!id!", str(member.id)),
                    overwrites={
                        member.guild.default_role: discord.PermissionOverwrite(
                            view_channel=False
                        ),
                        role: (perm := discord.PermissionOverwrite(
                            view_channel=True
                        )), member.guild.me: perm
                    } if (role := member.guild.get_role(row[1])) else {
                        member.guild.default_role: discord.PermissionOverwrite(
                            view_channel=True
                        )
                    }
                )
                await self.add_created(channel.id, row[0], member.id)

    @commands.Cog.listener()
    async def on_voice_join(self, member, _, vc):
        await self.on_update(member, vc.channel)


def setup(bot):
    bot.add_cog(VCChannel(bot))
