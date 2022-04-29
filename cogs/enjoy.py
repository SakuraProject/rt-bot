# Free RT - Enjoy Cog

from __future__ import annotations

from typing import Iterator

from discord.ext import commands
import discord

from jishaku.functools import executor_function
from aiofiles.os import remove
from bs4 import BeautifulSoup
from PIL import Image

from util.page import EmbedPage
from util import RT


class Enjoy(commands.Cog):
    def __init__(self, bot: RT):
        self.bot = bot

    @commands.command(
        aliases=["mc", "まいくら", "マイクラ"],
        extras={
            "headding": {"ja": "Minecraftの特定のユーザーのスキンとUUIDを調べます。",
                         "en": "Search Minecraft user's skin and uuid."},
            "parent": "Entertainment"
        }
    )
    @commands.cooldown(1, 15, commands.BucketType.user)
    async def minecraft(self, ctx, *, user):
        """!lang ja
        --------
        Minecraft Java版のユーザーのスキンとUUIDを検索します。

        Parameters
        ----------
        user_name : str
            ユーザー名です。

        Examples
        --------
        `rf!minecraft tasuren`

        Aliases
        -------
        mc, まいくら, マイクラ

        !lang en
        --------
        Search Minecraft JE User's skin and UUID.

        Parameters
        ----------
        user_name : str
            Minecraft JE user name.

        Examples
        --------
        `rf!minecraft tasuren`

        Aliases
        -------
        mc"""
        await ctx.trigger_typing()
        async with self.bot.session.get(
            f"https://api.mojang.com/users/profiles/minecraft/{user}"
        ) as r:
            if r.status == 204:
                await ctx.reply(
                    {"ja": "そのユーザーが見つかりませんでした。",
                     "en": "Not found that user."}
                )
            else:
                embed = discord.Embed(
                    title=user,
                    color=self.bot.colors["normal"]
                )
                embed.add_field(name="UUID", value=f"`{(await r.json())['id']}`")
                embed.set_image(
                    url=f"https://minecraft.tools/en/skins/getskin.php?name={user}"
                )
                await ctx.reply(embed=embed, replace_language=False)

    async def get_nhk(self) -> dict:
        "NHKのデータを取得します。"
        async with self.bot.session.get(
            "https://www3.nhk.or.jp/news/json16/syuyo.json"
        ) as r:
            return (await r.json())["channel"]

    NHK_BASE_URL = "https://www3.nhk.or.jp/news/"

    @commands.command(
        extras={
            "headding": {"ja": "NHKのニュースを取得します。",
                         "en": "Show japan nhk news."},
            "parent": "Individual"
        }
    )
    @commands.cooldown(1, 30, commands.BucketType.user)
    async def nhk(self, ctx):
        """!lang ja
        --------
        最新のNHKのニュースを取得します。

        !lang en
        --------
        Ah, This command language is supported only japanese."""
        await ctx.trigger_typing()
        data = await self.get_nhk()
        embeds = []
        for item in data["item"]:
            embed = discord.Embed(
                title=item["title"],
                url=f'{self.NHK_BASE_URL}{item["link"]}',
                color=0x0076d1
            )
            if item["relationLink"]:
                embed.add_field(
                    name="関連リンク",
                    value="\n".join(
                        f"・[{link['title']}](https:{link['link']})"
                        for link in item["relationLink"]
                    )
                )
            embed.set_thumbnail(
                url=f'{self.NHK_BASE_URL}{item["imgPath"]}'
            )
            embed.set_footer(
                text="NHKニュース",
                icon_url="https://www3.nhk.or.jp/news/parts16/images/favicon/apple-touch-icon-180x180-precomposed.png"
            )
            embeds.append(embed)
        await ctx.reply(embed=embeds[0], view=EmbedPage(data=embeds), replace_language=False)

    async def jin(self) -> Iterator[list[dict[str, str]]]:
        async with self.bot.session.get("http://jin115.com") as r:
            soup = BeautifulSoup(await r.text(), "html.parser")
        for article_soup in soup.find_all("div", class_="index_article_body"):
            thumbnail_anchor = article_soup.find("a")
            yield {
                "title": thumbnail_anchor.get("title"),
                "url": thumbnail_anchor.get("href"),
                "image": thumbnail_anchor.find("img").get("src")
            }

    @commands.command("jin", extras={
        "headding": {"ja": "オレ的ゲーム速報＠刃の最新のニュースを表示します。",
                     "en": "..."},
        "parent": "Entertainment"
    })
    @commands.cooldown(1, 30, commands.BucketType.user)
    async def jin_(self, ctx):
        """!lang ja
        --------
        [オレ的ゲーム速報＠刃](http://jin115.com)の最新のニュースを表示します。

        !lang en
        --------
        Ah, This command language is supported only japanese."""
        await ctx.trigger_typing()
        embeds = []
        async for data in self.jin():
            embed = discord.Embed(
                title=data["title"],
                url=data["url"],
                color=0x1e92d9
            )
            embed.set_image(url=data["image"])
            embed.set_footer(
                text="オレ的ゲーム速報＠刃",
                icon_url="https://cdn.discordapp.com/attachments/706794659183329291/781532922507034664/a3ztm-t6lmd.png"
            )
            embeds.append(embed)
        await ctx.reply("**最新のオレ的ゲーム速報＠刃**", embed=embeds[0], view=EmbedPage(data=embeds))

    GAME_PACKAGE_SIZES = {
        "switch": ((370, 600), "L"),
        "ps4": ((653, 838), "1")
    }
    GAME_BASE_PATH = "data/images/game_maker/"
    GAME_SUPPORT_EXTS = ("png", "jpg", "PNG", "JPG", "GIF", "gif")
    GAME_SUPPORT_MODES = ("switch", "ps4")

    @executor_function
    def make_game_package(self, path: str, output_path: str, mode: str) -> None:
        base_image = Image.open(f"{self.GAME_BASE_PATH}{mode}_base.png")
        base_image.paste(
            Image.open(path).resize(self.GAME_PACKAGE_SIZES[mode][0]),
            Image.open(f"{self.GAME_BASE_PATH}{mode}_mask.png")
            .convert(self.GAME_PACKAGE_SIZES[mode][1])
        )
        base_image.save(output_path)

    @commands.command(
        name="game", extras={
            "headding": {"ja": "好きなゲームソフトパッケージ画像を作ります。",
                         "en": "..."},
            "parent": "Entertainment"
        }
    )
    @commands.cooldown(1, 10, commands.BucketType.user)
    async def game_package(self, ctx, mode):
        """!lang ja
        --------
        ゲームのパッケージ画像を作ります。  
        好きな画像を添付することで[例]のような画像を作ることができます。

        Parameters
        ----------
        mode : ゲーム機名
            スイッチの場合は`switch`でPS4の場合は`ps4`にしてください。

        Examples
        --------
        `rf!game ps4` ([NYN姉貴の画像](http://tasuren.syanari.com/RT/help/Entertainment/NYN姉貴.jpg)を添付して実行。)
        -> [実行結果](http://tasuren.syanari.com/RT/help/Entertainment/ps4_NYN姉貴.png)

        !lang en
        --------
        Create a package for your game.  
        You can create an image like the one shown in the example by attaching your favorite image.

        Parameters
        ----------
        mode : Name of the game console
            Use `switch` for switch and `ps4` for PS4.

        Examples
        --------
        `rf!game ps4` ([NYN sister's image](http://tasuren.syanari.com/RT/help/Entertainment/NYN姉貴.jpg) is attached and executed.)
        -> [Execution result](http://tasuren.syanari.com/RT/help/Entertainment/ps4_NYN姉貴.png)"""
        if mode not in self.GAME_SUPPORT_MODES:
            return await ctx.reply(
                {"ja": "そのゲームは対応していません。",
                 "en": "That game is not supported."}
            )
        if not ctx.message.attachments:
            return await ctx.reply(
                {"ja": "画像を添付してください。",
                 "en": "You should send picture with command message."}
            )
        at = ctx.message.attachments[0]
        if not at.filename.endswith(self.GAME_SUPPORT_EXTS):
            return await ctx.reply(
                {"ja": f"そのファイルタイプは対応していません。\nサポートしている拡張子:{', '.join(self.GAME_SUPPORT_EXTS)}",
                 "en": f"Sorry, I don't know that file type.\nSupported file type:{', '.join(self.GAME_SUPPORT_EXTS)}"}
            )
        await ctx.trigger_typing()
        input_path = f"{self.GAME_BASE_PATH}input_{ctx.author.id}.{at.filename[at.filename.rfind('.'):]}"
        await at.save(input_path)
        await self.make_game_package(
            input_path,
            (output_path := f"{self.GAME_BASE_PATH}output_{ctx.author.id}.png"),
            mode
        )
        await ctx.reply(file=discord.File(output_path))
        for path in (input_path, output_path):
            await remove(path)


def setup(bot):
    bot.add_cog(Enjoy(bot))
