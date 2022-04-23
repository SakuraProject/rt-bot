# Free RT - AFK

from typing import TYPE_CHECKING, TypedDict, Optional, Dict

from discord.ext import commands, tasks
import discord

from util import RT

from datetime import datetime, timedelta
from collections import defaultdict
from ujson import loads, dumps
from asyncio import Event

if TYPE_CHECKING:
    from aiomysql import Pool


TABLES = ("AFK", "AFKPlus")
MAX_PLUS = 5


class DataManager:
    def __init__(self, cog: "AFK"):
        self.cog = cog
        self.pool: "Pool" = cog.bot.mysql.pool
        self.cog.bot.loop.create_task(self._prepare_table())

    async def _prepare_table(self):
        # テーブルの準備をする。このクラスのインスタンス化時に自動で実行される。
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"""CREATE TABLE IF NOT EXISTS {TABLES[0]} (
                        UserID BIGINT PRIMARY KEY NOT NULL, Reason TEXT
                    );"""
                )
                await cursor.execute(
                    f"""CREATE TABLE IF NOT EXISTS {TABLES[1]} (
                        UserID BIGINT, Reason TEXT, Data JSON
                    );"""
                )
                # キャッシュを用意しておく。
                await cursor.execute(f"SELECT * FROM {TABLES[0]};")
                for row in await cursor.fetchall():
                    if row and row[1]:
                        self.cog.cache[row[0]] = row[1]
                await cursor.execute(f"SELECT * FROM {TABLES[1]};")
                for row in await cursor.fetchall():
                    if row:
                        self.cog.plus_cache[row[0]][row[1]] = loads(row[2])
        self.cog.ready.set()

    async def get(self, user: discord.User) -> "UserData":
        "ユーザーデータクラスを取得します。"
        return await UserData.get(self.cog, user)

    async def delete(self, user_id: int) -> None:
        "ユーザーのデータを削除します。"
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                for i in len(TABLES):
                    if ((i and user_id in self.cog.cache_plus)
                            or (not i and user_id in self.cog.cache)):
                        await cursor.execute(
                            f"DELETE FROM {TABLES[i]} WHERE UserID = %s;"
                        )
                        if i:
                            del self.cog.cache_plus[user_id]
                        else:
                            del self.cog.cache[user_id]


class PlusData(TypedDict, total=False):
    time: str
    word: str


class UserData:
    def __init__(self, cog: "AFK", user: discord.User):
        self.cog, self.user = cog, user
        self.pool: "Pool" = self.cog.bot.mysql.pool
        self.reason: Optional[str] = None
        self.pluses: Dict[str, PlusData] = {}

    @classmethod
    async def get(cls, cog: "AFK", user: discord.User):
        "ユーザーデータクラスを取得します。"
        self = cls(cog, user)
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"SELECT Reason FROM {TABLES[0]} WHERE UserID = %s;",
                    (self.user.id,)
                )
                if (row := await cursor.fetchone()):
                    self.reason = row[0]
                # AFK Plusのデータを読み込んでおく。
                await cursor.execute(
                    f"SELECT Reason, Data FROM {TABLES[1]} WHERE UserID = %s;",
                    (user.id,)
                )
                for row in await cursor.fetchall():
                    if row:
                        self.pluses[row[0]] = loads(row[1])
        return self

    async def set_afk(self, reason: Optional[str] = None) -> None:
        "AFKを設定します。"
        self.reason = reason
        if reason:
            self.cog.cache[self.user.id] = reason
        elif self.user.id in self.cog.cache:
            del self.cog.cache[self.user.id]
        if reason is None:
            reason = ""
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"""INSERT INTO {TABLES[0]} VALUES (%s, %s)
                        ON DUPLICATE KEY UPDATE Reason = %s;""",
                    (self.user.id, reason, reason)
                )

    async def delete_afk(self) -> None:
        "AFKを削除します。"
        await self.set_afk()

    async def set_plus(self, reason: str, data: PlusData) -> None:
        "AFKプラスを設定します。"
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                assert len(self.pluses) < MAX_PLUS, "これ以上設定することはできません。"
                if reason in self.pluses:
                    await cursor.execute(
                        f"UPDATE {TABLES[1]} SET Reason = %s, Data = %s WHERE UserID = %s;",
                        (reason, dumps(data), self.user.id)
                    )
                else:
                    await cursor.execute(
                        f"INSERT INTO {TABLES[1]} VALUES (%s, %s, %s);",
                        (self.user.id, reason, dumps(data))
                    )
                self.pluses[reason] = data
                self.cog.plus_cache[self.user.id][reason] = data

    async def delete_plus(self, data: PlusData) -> None:
        "AFKプラスを削除します。"
        for reason, d in self.pluses.items():
            if d == data:
                del self.pluses[reason]
                del self.cog.plus_cache[self.user.id][reason]
                async with self.pool.acquire() as conn:
                    async with conn.cursor() as cursor:
                        await cursor.execute(
                            f"""DELETE FROM {TABLES[1]}
                                WHERE UserID = %s AND Reason = %s;""",
                            (self.user.id, reason)
                        )
                break
        else:
            assert False, "そのAFKプラスは設定されていません。"


class AFK(commands.Cog, DataManager):

    CHECK_EMOJI = "<:check_mark:885714065106808864>"

    def __init__(self, bot: RT):
        self.bot, self.before = bot, ""
        self.cache: Dict[int, str] = {}
        self.plus_cache: Dict[int, Dict[str, PlusData]] = defaultdict(dict)
        super(commands.Cog, self).__init__(self)
        self.ready = Event()
        self.process_afk_plus.start()

    @commands.group(
        aliases=["留守"], extras={
            "headding": {
                "ja": "留守メッセージの設定 AFK機能",
                "en": "Setting up answering machine messages, AFK Feature"
            }, "parent": "Individual"
        }
    )
    async def afk(self, ctx: commands.Context):
        """!lang ja
        --------
        AFK機能で留守メッセージを設定することができます。  
        [この画像](https://rt-bot.com/img/other/afk.png)のようなことができます。  
        パソコンから離れている間にメンションされた際に留守であることを伝えるメッセージを送信することができます。  
        また時間指定で毎日自動でAFKを設定する機能や指定された言葉が含まれるメッセージを送信したらAFKを設定する機能もあります。  
        設定したAFKは自分で何かメッセージを送信すると解除されます。

        !lang en
        --------
        The AFK function allows you to set up an answering message.  
        You can do something like [this image](https://rt-bot.com/img/other/afk.png).  
        The AFK function can be used to send an answering machine message when you are away from your computer.  
        You can also set an automatic AFK every day by specifying a time, or set an AFK when a message containing a specified word is sent.  
        The set AFK will be canceled when you send any message."""
        if not ctx.invoked_subcommand:
            await ctx.reply(
                {"ja": "使用方法が違います。",
                 "en": "It is wrong way to use this command."}
            )

    HELP = ("Individual", "afk")

    @afk.command(
        "set", aliases=["s", "設定"],
        extras={
            "headding": {
                "ja": "AFKを設定します。",
                "en": "Set AFK"
            }
        }
    )
    async def set_(self, ctx: commands.Context, *, reason):
        """!lang ja
        --------
        AFKを設定します。

        Parameters
        ----------
        reason : str
            AFKの理由で誰かにメンションされた際に表示するものです。

        Examples
        --------
        `rf!afk set 現在説教タイムのため返信ができません。`

        Aliases
        -------
        s, 設定

        !lang en
        --------
        Sets the AFK.

        Parameters
        ----------
        reason : str
            The reason to be displayed when someone mentions the AFK reason.

        Examples
        --------
        `rf!afk set Cannot reply due to current sermon time.`

        Aliases
        -------
        s"""
        await ctx.trigger_typing()
        await (await self.get(ctx.author)).set_afk(reason)
        await ctx.reply("Ok")

    @afk.group(aliases=["p", "プラス"])
    async def plus(self, ctx: commands.Context):
        """!lang ja
        --------
        AFKの拡張です。  
        これを使えば時間指定でのAFK設定や特定の言葉が含まれるメッセージ送信によりAFKをONにするなどの設定ができます。

        Aliases
        -------
        p, プラス

        !lang en
        --------
        This is an extension of AFK.  
        With this, you can set the AFK to go off at a certain time, or when a message containing a certain word is sent.

        Aliases
        -------
        p"""
        await self.afk(ctx)

    def get_data(self, mode: str) -> PlusData:
        return {"time": mode} if ":" in mode else {"word": mode}

    @plus.command(
        "set", aliases=["s", "設定"], hedding={
            "ja": "AFKプラスの設定をします。", "en": "Setting for AFK Plus"
        }
    )
    async def set_plus(self, ctx: commands.Context, mode, *, reason):
        """!lang ja
        --------
        AFKプラスを設定します。

        Parameters
        ----------
        mode : str
            何時にAFKを設定するか、または何の言葉がメッセージにあったらAFKを設定するのかです。  
            例えば`23:00`にすれば毎晩十一時にAFKを設定するようになります。  
            また`学校`とすれば`学校`が含まれるメッセージを送信したらAFKを設定するようになります。  
            午前9時などは`9:00`ではなく、`09:00`のようにかならず0を入れましょう。  
            0が入っていないと`9:00`という言葉が含まれるメッセージが送信されたときにAFKになるようになります。
        reason : str
            AFK設定に使用する理由です。

        Examples
        --------
        例えば寝る時間にAFKを設定したいのなら以下のようにすることで毎晩十一時にAFKを自動で設定することができます。
        ```
        rf!afk plus set 23:00 現在tasurenは営業しておりません。
        またのお越しをお待ちしております。
        ```

        Aliases
        -------
        s, 設定

        !lang en
        --------
        Sets AFK plus.

        Parameters
        ----------
        mode : str
            This is what time to set AFK, or what word is in the message to set AFK.  
            For example, if you set it to `23:00`, it will set AFK at 11:00 every night.  
            And if you set it to `school`, the AFK will be set when a message containing `school` is sent.  
            Note that you might use `9:00` for 9:00 in the morning, etc., but this is not good, and you need to fill in the zeros, so use something like `09:00`.
        reason : str
            The reason used to set the AFK.

        Examples
        --------
        For example, if you want to set AFK at bedtime, you can use the following to set AFK automatically at 11:00 every night.
        ```
        rf!afk plus set 23:00 Currently tasuren is not open for business.
        We look forward to seeing you again.
        ```

        Aliases
        -------
        s"""
        if len(mode) <= 25:
            try:
                await (await self.get(ctx.author)).set_plus(
                    reason, self.get_data(mode)
                )
            except AssertionError:
                await ctx.reply(
                    {"ja": "これ以上設定することはできません。",
                     "en": "No more can be added."}
                )
            else:
                await ctx.reply("Ok")
        else:
            await ctx.reply(
                {"ja": "modeは25文字以下である必要があります。",
                 "en": "Mode length must be less than 25."}
            )

    @plus.command(
        aliases=["del", "削除"],
        extras={
            "headding": {
                "ja": "AFKプラスの設定を削除します。", "en": "Delete AFK Plus"
            }
        }
    )
    async def delete(self, ctx: commands.Context, *, mode):
        """!lang ja
        --------
        設定したAFKプラスを解除します。

        Parameters
        ----------
        mode : str
            AFKプラスの設定の際に入力した引数の`mode`です。

        Aliases
        -------
        del, 削除

        !lang en
        --------
        Cancels the AFK plus setting.

        Parameters
        ----------
        mode : str
            This is the `mode` argument you entered when setting AFK plus.

        Aliases
        -------
        del"""
        try:
            await (await self.get(ctx.author)).delete_plus(self.get_data(mode))
        except AssertionError:
            await ctx.reply(
                {"ja": "そのAFKプラスの設定が見つかりませんでした。",
                 "en": "The afk plus setting is not found."}
            )
        else:
            await ctx.reply("Ok")

    @plus.command(
        "list", aliases=["l", "一覧"],
        extras={
            "headding": {
                "ja": "AFK Plusの設定リストを表示します。",
                "en": "Show you the settings of AFK Plus."
            }
        }
    )
    async def list_(self, ctx: commands.Context):
        """!lang ja
        --------
        設定しているAFKプラスの一覧を表示します。

        !lang en
        --------
        Displays a list of configured AFK Plus."""
        data = await self.get(ctx.author)
        embed = discord.Embed(
            title=self.__cog_name__, color=self.bot.colors["normal"]
        )
        for reason in data.pluses:
            embed.add_field(
                name=(
                    data.pluses[reason].get("time")
                    or data.pluses[reason].get("word")
                ),
                value=reason
            )
        await ctx.reply(embed=embed)

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if (message.content.startswith(tuple(self.bot.command_prefix))
                or not message.guild or message.author.bot):
            return

        if message.author.id in self.cache:
            # もしAFKを設定していた人ならAFKを解除しておく。
            await (await self.get(message.author)).delete_afk()
            return await message.reply(
                "AFKを解除しました。", delete_after=3
            )

        # AFKを設定している人にメンションをしているのならAFKだと伝える。
        for user in message.mentions:
            if user.id in self.cache:
                await message.channel.webhook_send(
                    content=self.cache[user.id],
                    avatar_url=user.avatar.url if user.avatar else "",
                    username=f"{user.name} - RT 留守メッセージ AFK"
                )

        # AFKプラスのワードフックがメッセージにあるならAFKを設定する。
        if message.author.id in self.plus_cache:
            for reason, data in self.plus_cache[message.author.id].items():
                if data.get("word", "fdjasklfdsaj;fla") in message.content:
                    await (await self.get(message.author)).set_afk(reason)
                    await message.add_reaction(self.CHECK_EMOJI)
                    break

    @tasks.loop(seconds=10)
    async def process_afk_plus(self):
        # AFKプラスの時間指定のAFKを設定する。
        await self.ready.wait()
        now = datetime.now()
        if not self.bot.test:
            now += timedelta(hours=9)
        now = now.strftime("%H:%M")

        if self.before != now:
            self.before = now

            for user_id, datas in list(self.plus_cache.items()):
                for reason, data in datas.items():
                    if data.get("time", "") == now:
                        if (user := self.bot.get_user(user_id)):
                            await (await self.get(user)).set_afk(reason)
                        else:
                            # もしユーザーが見つからなかったのならそのデータを削除する。
                            await self.delete(user_id)

    def cog_unload(self):
        self.process_afk_plus.cancel()


def setup(bot):
    bot.add_cog(AFK(bot))
