# Free RT - Short URL

from discord.ext import commands
import discord

from util.mysql_manager import DatabaseManager
from util import RT

from random import sample
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
                ORDER BY Reg ASC;""",
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

    async def getrealall(self, cursor) -> list:
        return [
            row async for row in cursor.get_datas(self.DB, {}) if row
        ]


CHARS = list(range(41, 91)) + list(range(61, 123))


def random_string(length: int) -> str:
    return "".join(map(str, sample(CHARS, length)))


class ShortURL(commands.Cog, DataManager):
    def __init__(self, bot: RT):
        self.bot = bot
        self.bot.loop.create_task(self.init_database())

    async def init_database(self):
        super(commands.Cog, self).__init__(self.bot.mysql)
        await self.init_table()

    @commands.Cog.listener("on_update_api")
    async def update_cache(self):
        async with self.bot.session.post(
            f"{self.bot.get_url()}/api/shorturl", json={
                row[2]: row[1] for row in await self.getrealall()
            }
        ):  # as r:
            # self.bot.print("[ShortURL_CacheUpdater]", await r.json())
            ...

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

    ALLOWED_CHARACTERS = "".join(
        "".join(chr(i) for i in range(x, y)) for x, y in (
            (48, 58), (65, 91), (97, 123)
        )
    )
    HELP = ("Individual", "url")

    @url.command(
        aliases=["短縮", "add"],
        extras={
            "headding": {
                "ja": "URLを短縮します。",
                "en": "Shortens URL"
            }
        }
    )
    async def short(self, ctx, url: str, custom: str = None):
        """!lang ja
        --------
        URLを短縮します。

        Warnings
        --------
        これは15個まで作成可能です。  
        15個以上作った場合は自動で一番古い短縮URLが無効になります。

        Parameters
        ----------
        url : str
            対象のURLです。
        custom : str, optional
            短縮URLをカスタマイズする場合に使います。  
            例えば`tasuren`にすれば`http://rtbo.tk/tasuren`のように短縮されます。  
            ひらがななどは使用できないので英数字にしてください。  
            空白の場合はランダムな六文字のアルファベットとなります。

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
            else:
                return await ctx.reply("すみませんが作れませんでした。\nもう一回やってみてください。")
        elif not all(char in self.ALLOWED_CHARACTERS for char in custom):
            return await ctx.reply(
                f"以下の文字しか使用できません。\n`{self.ALLOWED_CHARACTERS}`"
            )

        try:
            await self.add(ctx.author.id, url, custom)
        except AssertionError:
            await ctx.reply("その短縮URLは既に存在するので作れません。")
        else:
            await self.update_cache()
            await ctx.reply(f"短縮しました。>>>http://rtbo.tk/{custom}")

    @url.command(
        "list", aliases=["一覧"], 
        extras={
            "headding": {
                "ja": "短縮したURLのリストを表示します。",
                "en": "Displays shorted URLs"
            }
        }
    )
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

    @url.command(
        "remove", aliases=["rm", "delete", "del", "削除"], 
        extras={
            "headding": {
                "ja": "短縮URLを削除します。", "en": "Remove shorted URL"
            }
        }
    )
    async def remove_(
        self, ctx, custom="URLの最後の部分です。 (End of URL (`...` of `http://rtbo.tk/...`))"
    ):
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
            `http://rtbo.tk/... ` or `.... `.

        Aliases
        -------
        rm, delete, del"""
        if "http://rtbo.tk/" in custom:
            custom = custom[16:]
        try:
            await self.remove(ctx.author.id, custom)
        except AssertionError:
            await ctx.reply("その短縮URLが見つかりませんでした。")
        else:
            await self.update_cache()
            await ctx.reply("その短縮URLを削除しました。")


def setup(bot):
    bot.add_cog(ShortURL(bot))
