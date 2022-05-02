# Free RT - News

from datetime import datetime
from time import time

from discord.ext import commands
import discord

from util.mysql_manager import DatabaseManager
from util.page import EmbedPage


class DataManager(DatabaseManager):
    def __init__(self, db):
        self.db = db

    async def init_table(self, cursor) -> None:
        await cursor.create_table(
            "news", {
                "id": "BIGINT", "time": "TEXT",
                "content": "TEXT", "image": "TEXT"
            }
        )

    async def add_news(self, cursor, content: str, image: str) -> float:
        # Newsを新しく追加します。
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        t = int(time())
        await cursor.insert_data(
            "news", {"id": t, "time": now, "content": content, "image": image}
        )
        return t

    async def remove_news(self, cursor, id_: int) -> None:
        # Newsを削除します。
        await cursor.delete("news", {"id": id_})

    async def get_news(self, cursor, id_: int) -> tuple:
        # Newsを取得する。
        return (await cursor.get_data("news", {"id": id_}))

    async def get_news_all(self, cursor) -> list:
        # Newsを全て取得する。
        return [row async for row in cursor.get_datas(
                "news", {}, custom="ORDER BY id DESC")
                if row]


class News(commands.Cog, DataManager):
    def __init__(self, bot):
        self.bot, self.rt = bot, bot.data
        self.bot.loop.create_task(self._on_ready())

    async def _on_ready(self):
        super(commands.Cog, self).__init__(self.bot.mysql)
        await self.init_table()

    async def get_rows(self) -> list:
        return reversed(await self.get_news_all())

    def convert_embed(self, doc: str) -> discord.Embed:
        # マークダウンをEmbedにする。
        i = doc.find("\n")
        title = doc if i == -1 else doc[:i]
        description = doc[i:(i := doc.find("## "))]
        embed = discord.Embed(
            title=title[2:] if title.startswith("# ") else title,
            description=description
        )
        values = doc[i:].replace("### ", "**#** ").split("## ")
        for value in values:
            if value:
                name = value[:(i := value.find("\n"))]
                name = "?\n" + name
                embed.add_field(name=name, value=value[i:], inline=False)
        return embed

    @commands.group(
        extras={
            "headding": {
                "en": "Show RT's news.",
                "ja": "RTのニュースを表示します。"
            },
            "parent": "RT"
        }
    )
    async def news(self, ctx):
        """!lang ja
        --------
        最新のニュースを表示します。  
        `rt!news`だけでいいです。  
        下にあるadd/removeはRT管理者のみ実行可能です。

        !lang en
        --------
        Show RT's news."""
        if not ctx.invoked_subcommand:
            embeds, i = [], 0
            for row in await self.get_news_all():
                i += 1
                embed = self.convert_embed(row[2])
                embed.title = f"{embed.title}"
                embed.set_footer(text=f"{row[1]} | ID:{row[0]}")
                if row[3] != "None":
                    embed.set_image(url=row[3])
                embeds.append(embed)
                if i == 10:
                    break
            if embeds:
                await ctx.reply(
                    "**最新のRTニュース**", embed=embeds[0], view=EmbedPage(data=embeds)
                )
            else:
                await ctx.reply("Newsは現在空です。")

    @news.command()
    async def add(self, ctx, *, content):
        """!lang ja
        --------
        ニュースに新しくなにかを追加します。  

        Parameters
        ----------
        image : str
            写真のURLです。  
            写真がないのなら`None`を入れてください。
        content : str
            ニュースに追加する文字列です。"""
        if ctx.author.id in (
            634763612535390209, 667319675176091659,
            693025129806037003, 739702692393517076,
            510590521811402752
        ):
            now = await self.add_news(content, "None")
            await ctx.reply(f"Ok number:{now}")

    @news.command()
    async def remove(self, ctx, id_: int):
        """!lang ja
        --------
        ニュースを削除します。

        Parameters
        ----------
        id : int
            削除するニュースのidです。"""
        if ctx.author.id in (
            634763612535390209, 667319675176091659,
            693025129806037003, 739702692393517076,
            510590521811402752
        ):
            await self.remove_news(id_)
            await ctx.reply("Ok")


async def setup(bot):
    await bot.add_cog(News(bot))
