# Free RT - Force Pinned Message

from typing import Optional, Tuple, Dict, List

from collections import defaultdict
from time import time

from discord.ext import commands, tasks
import discord

from util import RT
from util.mysql_manager import DatabaseManager as OldDatabaseManager
from util import DatabaseManager, markdowns

from aiomysql import Pool, Cursor
from ujson import loads, dumps


class DataManager(OldDatabaseManager):

    TABLE = "ForcePinnedMessage"

    def __init__(self, db):
        self.db = db

    async def init_table(self, cursor) -> None:
        await cursor.create_table(
            self.TABLE, dict(
                GuildID="BIGINT", ChannelID="BIGINT", AuthorID="BIGINT",
                MessageID="BIGINT", Bool="TINYINT", Text="TEXT"
            )
        )
        await self._update_cache(cursor)

    async def _update_cache(self, cursor):
        async for row in cursor.get_datas(self.TABLE, {}):
            if row:
                self.cache[row[0]].append(row[1])

    async def update_cache(self, cursor):
        return await self._update_cache(cursor)

    async def setting(
        self, cursor, guild_id: int, channel_id: int,
        message_id: int, author_id: int,
        onoff: bool, text: str
    ) -> None:
        value = dict(Bool=int(onoff), Text=text,
                     AuthorID=author_id, MessageID=message_id)
        target = dict(GuildID=guild_id, ChannelID=channel_id)
        if await cursor.exists(self.TABLE, target):
            await cursor.update_data(self.TABLE, value, target)
        else:
            value.update(target)
            await cursor.insert_data(self.TABLE, value)

    async def delete(self, cursor, channel_id: int) -> None:
        target = {"ChannelID": channel_id}
        if await cursor.exists(self.TABLE, target):
            await cursor.delete(self.TABLE, target)

    async def get(
        self, cursor, guild_id: int, channel_id: int
    ) -> Tuple[int, int, bool, str]:
        target = dict(GuildID=guild_id, ChannelID=channel_id)
        if await cursor.exists(self.TABLE, target):
            if (row := await cursor.get_data(self.TABLE, target)):
                return row[-4], row[-3], bool(row[-2]), row[-1]
            else:
                return 0, 0, False, ""
        else:
            return 0, 0, False, ""


class IntervalDataManager(DatabaseManager):

    TABLE = "ForcePinnedMessageInterval"

    def __init__(self, cog: "ForcePinnedMessage"):
        self.cog = cog
        self.pool: Pool = self.cog.bot.mysql.pool
        self.cog.bot.loop.create_task(self.prepare_table())

    async def prepare_table(self, cursor: Cursor = None) -> None:
        "テーブルを準備する。クラスのインスタンス化時に自動で実行されます。"
        await cursor.execute(
            f"""CREATE TABLE IF NOT EXISTS {self.TABLE} (
                ChannelID BIGINT NOT NULL PRIMARY KEY, Minutes FLOAT
            );"""
        )

    async def write(
        self, channel_id: int, minutes: float, cursor: Cursor = None
    ) -> None:
        "インターバルを書き込みます。"
        await cursor.execute(
            f"""INSERT INTO {self.TABLE} VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE Minutes = %s;""",
            (channel_id, minutes, minutes)
        )

    async def read(self, channel_id: int, cursor: Cursor = None) -> float:
        "インターバルを取得します。見つからなければ`5.0`が返されます。"
        await cursor.execute(
            f"SELECT Minutes FROM {self.TABLE} WHERE ChannelID = %s;",
            (channel_id,)
        )
        if (row := await cursor.fetchone()):
            return row[0]
        else:
            return 5.0


class ForcePinnedMessage(commands.Cog, DataManager):
    def __init__(self, bot: RT):
        self.bot = bot
        self.queue: Dict[int, Tuple[discord.Message, float]] = {}
        self.remove_queue: List[int] = []
        self.cache: Dict[int, List[int]] = defaultdict(list)
        self.bot.loop.create_task(self.on_ready())
        self.interval = IntervalDataManager(self)

    async def on_ready(self):
        await self.bot.wait_until_ready()
        super(commands.Cog, self).__init__(
            self.bot.mysql
        )
        await self.init_table()
        self.worker.start()

    @commands.command(
        extras={
            "headding": {
                "ja": "いつも下にくるメッセージ。強制ピン留めメッセージ機能。",
                "en": "Messages that always come to the bottom. Force pinned message function."
            },
            "parent": "ServerTool"
        }, aliases=["ピン留め", "ぴんどめ", "fpm", "forcepinmessage"]
    )
    @commands.has_guild_permissions(manage_messages=True)
    async def pin(self, ctx: commands.Context, onoff: bool, *, content=""):
        """!lang ja
        --------
        いつも下にくるメッセージを作ることができます。  
        メッセージ削除権限を持つ人のみ実行可能です。  
        別名`強制ピン留めメッセージ`です。

        Parameters
        ----------
        onoff : bool
            onにすると強制ピン留めメッセージを作ります。  
            もし強制ピン留めメッセージを無効にした際はこれをoffにしてください。
        content : str
            いつも下にくるメッセージの内容です。  
            onoffをoffにした際はこれは書かなくて良いです。

        Aliases
        -------
        fpm, forcepinmessage, ピン留め, ぴんどめ

        Examples
        --------
        ```
        rf!pin on 自己紹介テンプレート：
        名前：
        性別：
        一言：
        ```

        Notes
        -----
        下に来るメッセージは数秒毎に更新されるので数秒は下に来ないことがあります。  
        以下のように最初に`# `を置いて`embed`コマンドの書き方を使えば埋め込みにすることができます。
        ```
        rf!pin on # タイトル
        説明
        ## フィールド名
        フィールド内容
        ```
        また、送信頻度を一時間に一回などのしたい場合は`rf!pinit <何分>`を実行すると送信頻度を調節できます。  
        もし、強制ピン留めのメッセージのアイコンをRTにしたい、もしくは名前をカスタマイズしたいと言う場合は、チャンネルトピックに以下を追加してください。
        ```
        # 送信者の名前をカスタマイズしたい場合 #
        rt>fpm 名前
        # 送信者のアイコンをRTにしたい場合 #
        rt>fpm 名前 --rt-icon
        ```

        Warnings
        --------
        設定後はすぐに下にこないことがあります。  
        しばらくしても下に来ない際はメッセージを送ってみてください。  
        これはRTがメッセージを送りすぎてAPI制限になるということを防止するために発生するものでご了承ください。

        !lang en
        --------
        You can create a message that always comes at the bottom.  
        This can only be done by someone with the Delete Message permission.  
        Also known as a force pinned message.

        Parameters
        ----------
        onoff : bool
            When set to "on", this function creates a forced pinning message.  
            If you want to disable the forced pinning message, set this to off.
        content : str
            The content of the message that always appears below.  
            If you turn off onoff, you do not need to write this.

        Aliases
        -------
        fpm, forcepinmessage

        Examples
        --------
        ```
        rf!pin on Self-introduction template:
        Name:
        Gender:
        Comment:
        ```

        Warnings
        --------
        After setting it up, it may not come down immediately.  
        If it doesn't come down after a while, please try sending a message.  
        Please note that this is to prevent RTs from sending too many messages, which would limit the API."""
        if hasattr(ctx.channel, "topic"):
            await ctx.typing()

            if content.startswith("# "):
                # もし埋め込みならjsonにする。
                content = "<" + dumps(
                    markdowns.create_embed(
                        content, color=ctx.author.color
                    ).to_dict()
                ) + ">"

            # Saveをする。
            await self.setting(
                ctx.guild.id, ctx.channel.id, 0,
                ctx.author.id, onoff, content
            )

            # Queueなどの処理をする。
            if not onoff and ctx.channel.id in self.queue:
                del self.queue[ctx.channel.id]
                if ctx.channel.id not in self.remove_queue:
                    self.remove_queue.append(ctx.channel.id)
            if onoff and ctx.channel.id in self.remove_queue:
                self.remove_queue.remove(ctx.channel.id)
            await self.update_cache()

            await ctx.reply("Ok")
        else:
            await ctx.reply("スレッドに設定することはできません。")

    @commands.command()
    async def pinit(self, ctx: commands.Context, interval: float):
        if 0.083 <= interval <= 180:

            if ctx.channel.id in self.cache[ctx.guild.id]:
                await self.interval.write(ctx.channel.id, interval * 60)
                await ctx.reply("Ok")
            else:
                await ctx.reply("強制ピン留めがこのチャンネルには設定されていません。")
        else:
            await ctx.reply("インターバルは五秒から三時間までしか設定できません。")

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if not message.guild or "- RT" in message.author.name or not self.bot.is_ready():
            return

        if message.channel.id not in self.remove_queue:
            if (message.guild.id in self.cache
                    and message.channel.id in self.cache[message.guild.id]):
                self.queue[message.channel.id] = (message, time())

    def cog_unload(self):
        self.worker.cancel()

    @tasks.loop(seconds=5)
    async def worker(self):
        "Queueに入れられたメッセージを読み取って強制ピン留めのメッセージ送信を行います。"
        now = time()
        for channel_id, (message, time_) in list(self.queue.items()):
            # 事前処理
            if channel_id in self.remove_queue:
                self.remove_queue.remove(channel_id)
            if channel_id not in self.queue:
                continue

            # インターバルをチェックする。
            if now - time_ < await self.interval.read(channel_id):
                continue

            # 送信内容などの取得を行う。
            fpm = await self.get(message.guild.id, message.channel.id)

            # 前回のメッセージの削除を試みる。
            new_message = None
            if fpm[1] != 0:
                try:
                    before_message = await message.channel.fetch_message(fpm[1])

                    if before_message:
                        await before_message.delete()
                except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                    pass
            if channel_id in self.queue:
                del self.queue[channel_id]

            # メッセージなどの調整をする。
            member = message.guild.get_member(fpm[0])
            if member is None:
                member = self.bot.get_user(fpm[0])
            content = fpm[3]
            if isinstance(content, dict):
                kwargs = {"embed": discord.Embed.from_dict(content)}
            elif content.startswith("<") and content.endswith(">"):
                try:
                    data = loads(content[1:-1])
                    if isinstance(data, dict):
                        kwargs = {"embed": discord.Embed.from_dict(data)}
                    else:
                        raise ValueError("")
                except ValueError:
                    kwargs = {"content": content}
            else:
                kwargs = {"content": content}

            if member is not None:
                # メッセージの送信を行う。
                name = self.get_custom_name(message.channel, member) or (
                    getattr(member, 'display_name', member.name),
                    False
                )
                try:
                    new_message = await message.channel.webhook_send(
                        username=f"{name[0]} - RT",
                        avatar_url=self.bot.user.avatar.url if name[1] else member.avatar.url,
                        wait=True, **kwargs
                    )
                except Exception as e:
                    if not isinstance(e, (discord.Forbidden, discord.HTTPException)):
                        print("(ignore) Error on ForcePinnedMessage:", e)

            # 送信したメッセージを次消せるように記録しておく。
            if message.guild and message.channel and member:
                await self.setting(
                    message.guild.id, message.channel.id,
                    getattr(new_message, "id", 0),
                    member.id, True, fpm[3]
                )
            else:
                # もしチャンネルが見つからないなどの理由でメッセージ送信に失敗したなら設定を削除する。
                await self.delete(channel_id)

    def get_custom_name(
        self, channel: discord.TextChannel, member: discord.Member
    ) -> Optional[Tuple[str, bool]]:
        "カスタム名とアイコンをどうするかを取得する。"
        if hasattr(channel, "topic") and "rt>fpm " in (channel.topic or "..."):
            custom = channel.topic[channel.topic.find("rt>fpm"):]
            end = custom.find("\n")
            custom = custom[7:] if end == -1 else custom[7:end]
            del end
            if "--rt-icon" in custom:
                custom = custom.replace("--rt-icon", "")
                custom += "1"
            else:
                custom += "0"
            return custom[:-1].replace(
                "!name!", getattr(member, "display_name", member.name)
            ), custom[-1] == "1"


async def setup(bot):
    await bot.add_cog(ForcePinnedMessage(bot))
