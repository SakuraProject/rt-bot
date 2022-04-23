# Free RT - Short URL

from discord.ext import commands
import discord

from util import DatabaseManager, WebManager

from sanic.response import redirect
from urllib.parse import urlparse
from random import sample, choice
from time import time


class DataManager(DatabaseManager):

    DB = "ShortURL"

    def __init__(self, db):
        self.db = db

    async def init_table(self, cursor):
        await cursor.create_table(
            self.DB, {
                "UserID": "BIGINT", "Url": "TEXT", "Custom": "TEXT",
                "Reg": "BIGINT"
            }
        )

    async def add(self, cursor, user_id: int, url: str, custom: str) -> None:
        target = {"Url": url, "Custom": custom}
        assert not await cursor.exists(self.DB, target), "そのデータが既に存在します。"
        target["UserID"] = user_id
        target["Reg"] = int(time())
        await cursor.insert_data(self.DB, target)

    async def remove_last(self, cursor, user_id: int) -> None:
        await cursor.cursor.execute(
            """SELECT * FROM ShortURL
                WHERE UserID = %s
                ORDER BY Reg ASC""",
            (user_id,)
        )
        row = await cursor.cursor.fetchone()
        if row:
            await cursor.delete(self.DB, {"UserID": user_id, "Custom": row[2]})

    async def remove(self, cursor, user_id: int, custom: str) -> None:
        target = {"UserID": user_id, "Custom": custom}
        assert await cursor.exists(self.DB, target), "そのデータが見つかりませんでした。"
        await cursor.delete(self.DB, target)

    async def getall(self, cursor, user_id: int) -> list:
        return [
            row async for row in cursor.get_datas(
                self.DB, {"UserID": user_id}
            ) if row
        ]

    async def get(self, cursor, custom: str) -> str:
        target = {"Custom": custom}
        assert await cursor.exists(self.DB, target), "見つかりませんでした。"
        return (await cursor.get_data(self.DB, target))[1]

CHARS = list(range(41, 91)) + list(range(61, 123))


def random_string(length: int) -> str:
    return "".join(map(str, sample(CHARS, length)))


class ShortURL(commands.Cog, DataManager):
    def __init__(self, bot):
        self.bot = bot
        self.bot.loop.create_task(self.init_database())

    async def init_database(self):
        super(commands.Cog, self).__init__(self.bot.mysql)
        await self.init_table()

    @commands.group(
        extras={
            "headding": {
                "ja": "URL短縮", "en": "Shorten the url."
            }, "parent": "Individual"
        }
    )
    async def url(self, ctx):
        """!lang ja
        --------
        URLを短縮します。

        !lang en
        --------
        Shorten the URL."""
        if not ctx.invoked_subcommand:
            await ctx.reply("使用方法が違います。")

    @url.command(aliases=["短縮", "add"])
    async def short(self, ctx, url: str, custom: str = None):
        """!lang ja
        --------
        URLを短縮します。

        Warnings
        --------
        これは1人につき15個までしか作成できません。  
        15個以上作った場合は自動で一番古い短縮URLが無効になります。

        Parameters
        ----------
        url : str
            対象のURLです。
        custom : str, optional
            短縮URLをカスタムする場合に使います。  
            例えば`tasuren`にすれば`http://rtbo.tk/tasuren`のように短縮されます。  
            これはひらがななどは使えないので英数字にしてください。  
            空白の場合はランダムな六文字の英文字となります。

        Examples
        --------
        `rf!url short http://tasuren.f5.si tasuren`  
        tasurenのホームページを`http://rtbo.tk/tasuren`からアクセスできるようにする。

        Aliases
        -------
        短縮, add

        !lang en
        --------
        Shortens a URL.

        Warnings
        --------
        You can create up to 15 of these.  
        If you create more than 15, the oldest shortened URL will be invalidated automatically.

        Parameters
        ----------
        url : str
            The target URL.
        custom : str, optional
            Use this to customize a shortened URL.  
            For example, `tasuren` will shorten the URL to `https://rtbo.tk/tasuren`.  
            This should be alphanumeric, since hiragana is not allowed.  
            If it is blank, it will be a random six-character alphanumeric string.

        Examples
        --------
        `rf!url short http://tasuren.f5.si tasuren`  
        Make the home page of tasuren accessible from `http://rtbo.tk/tasuren`."""
        if len(await self.getall(ctx.author.id)) >= 15:
            await self.remove_last(ctx.author.id)

        if custom is None:
            for _ in range(10):
                custom = random_string(6)
                try:
                    await self.get(custom)
                except AssertionError:
                    break

        try:
            await self.add(ctx.author.id, url, custom)
        except AssertionError:
            if custom is None:
                return await ctx.reply("申し訳ありませんが、何らかの理由で作成に失敗しました。\nもう一度やってみてください。")
            await ctx.reply("その短縮URLは既に存在するので作れません。")
        else:
            await ctx.reply(f"短縮しました。>>>http://rtbo.tk/{custom}")

    @url.command("list", aliases=["一覧"])
    async def list_(self, ctx):
        """!lang ja
        --------
        登録している短縮URLのリストを表示します。

        Aliases
        -------
        一覧

        !lang en
        --------
        Display you registered short urls."""
        rows = await self.getall(ctx.author.id)
        if rows:
            await ctx.reply(
                embed=discord.Embed(
                    title="短縮URL一覧",
                    description="\n".join(
                        f"* http://rtbo.tk/{row[2]}"
                        for row in rows if row
                    ), color=self.bot.colors["normal"]
                )
            )
        else:
            await ctx.reply("まだ何も短縮URLは登録されていません。")

    @url.command("remove", aliases=["rm", "delete", "del", "削除"])
    async def remove_(self, ctx, custom):
        """!lang ja
        --------
        登録している短縮URLを削除します。

        Parameters
        ----------
        custom : str
            短縮URLのアドレスです。  
            `http://rtbo.tk/...`か`...`です。

        Aliases
        -------
        rm, delete, del, 削除

        !lang en
        --------
        Deletes a registered shortened URL.

        Parameters
        ----------
        custom : str
            The address of the shortened URL.  
            `http://rtbo.tk/... ` or `...`.

        Aliases
        -------
        rm, delete, del"""
        try:
            url = urlparse(url)
        except ValueError:
            return await ctx.reply("正しいURLを入力してください。")
        try:
            await self.remove(ctx.author.id, url.path)
        except AssertionError:
            await ctx.reply("その短縮URLが見つかりませんでした。")
        else:
            await ctx.reply(f"短縮URL`{url.path}`を削除しました。")

    ROUTINE_URLS = (
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://www.youtube.com/watch?v=ok7UX3utzvI",
        "https://www.youtube.com/watch?v=lO9alUUIopI",
        "https://www.youtube.com/watch?v=p1pu96oz9Q4",
        "https://www.youtube.com/watch?v=yJ9hikxlGpU",
        "https://www.youtube.com/watch?v=H221MRRgFZs"
    )
    HOSTS = ("localhost", "rtbo.tk")

    @commands.Cog.route("/<custom>", host=HOSTS[1])
    @WebManager.cooldown(3)
    async def short_url(self, _, custom: str):
        try:
            url = await self.get(custom)
        except AssertionError:
            url = choice(self.ROUTINE_URLS)
        return redirect(url)


def setup(bot):
    bot.add_cog(ShortURL(bot))
