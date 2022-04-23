# Free RT - Funp

from discord.ext import commands, easy
import discord

from util.mysql_manager import DatabaseManager
from random import choice


class DataManager(DatabaseManager):

    DB = "Funp"

    def __init__(self, db):
        self.db = db

    async def init_table(self, cursor) -> None:
        await cursor.create_table(
            self.DB, {
                "UserID": "BIGINT", "Name": "TEXT",
                "Url": "TEXT", "Mode": "TEXT"
            }
        )

    async def write(self, cursor, user_id: int, name: str, url: str, mode: str) -> None:
        target = {
            "UserID": user_id, "Name": name,
            "Url": url, "Mode": mode
        }
        if await cursor.exists(self.DB, target):
            raise ValueError("既にその画像は登録されています。")
        else:
            await cursor.insert_data(self.DB, target)

    async def read(self, cursor, mode: str) -> tuple:
        await cursor.cursor.execute(
            """SELECT * FROM Funp
                WHERE Mode = %s
                ORDER BY RAND()
                LIMIT 3""",
            (mode,)
        )
        return choice(
            [row for row in await cursor.cursor.fetchall()
             if row is not None]
        )

    async def delete(self, cursor, user_id: int, name: str, mode: str) -> None:
        target = {
            "UserID": user_id, "Name": name, "Mode": mode
        }
        if await cursor.exists(self.DB, target):
            await cursor.delete(self.DB, target)
        else:
            raise KeyError("そのFunpが見つかりませんでした。")

    async def get_list(self, cursor, user_id:int, mode:str) -> list:
        if not await cursor.exists(self.DB, {"UserID":user_id, "Mode":mode}):
            raise KeyError("Funpがありません。")
        await cursor.cursor.execute(
            """SELECT * FROM Funp
                WHERE Mode = %s AND UserID = %s""",
            (mode, user_id)
        )
        return [row for row in await cursor.cursor.fetchall()
                if row is not None]

    
async def callback(view, interaction):
    view = easy.View("FunpTwo")
    view.add_item(
        discord.ui.Button, None, label="サポートサーバーに行く。",
        url="https://discord.gg/ugMGw5w"
    )
    await interaction.response.send_message(
        ("Funpのメッセージを削除しました。\n通報する場合は下から行けます。"
         f"\n通報する際は`{interaction.message.embeds[0].description}"
         f" - {interaction.message.embeds[0].title}`"
         "をRTサーバーの管理者に伝えてください。"),
        view=view()
    )
    await interaction.message.delete()


warn_view = easy.View("WarnButtonFunp", timeout=None)
warn_view.add_item(
    discord.ui.Button, callback, label="緊急メッセージ削除ボタン",
    style=discord.ButtonStyle.danger, custom_id="warnbuttonfunp"
)
warn_view = warn_view()


class Funp(commands.Cog, DataManager):

    MODES = {
        "normal": ["normal", "question", "cute"],
        "nsfw": ["2d", "cg", "3d"]
    }
    ALIASES = {
        "普通": "normal",
        "問題": "question",
        "二次元": "2d", "三次元": "3d",
        "CG": "cg", "癒し": "cute"
    }

    def __init__(self, bot):
        self.bot = bot
        self.bot.add_view(warn_view)
        self.bot.loop.create_task(self.on_ready())

    async def on_ready(self):
        super(commands.Cog, self).__init__(
            self.bot.mysql
        )
        await self.init_table()

    MODE_OPTION = discord.SlashOption(
        "category", "表示するみんなの画像のカテゴリーです。",
        choices={
            "普通": "normal",
            "問題": "question",
            "癒し": "cute",
            "二次元 (nsfw)": "2d",
            "CG (2.5次元, nsfw)": "cg",
            "三次元 (nsfw)": "3d"
        }
    )

    @commands.group(
        slash_command=True, extras={
            "headding": {
                "ja": "みんなの画像を見る。",
                "en": "Not setting yet"
            }, "parent": "Entertainment"
        }
    )
    @commands.cooldown(1, 4, commands.BucketType.user)
    async def funp(self, ctx):
        """!lang ja
        ---------
        みんなの画像機能です。
        おもしろ画像などカテゴリー別にユーザーが登録した画像を見ることができます。  
        そして、自分で画像を登録することもできます。

        Notes
        -----
        カテゴリ一覧 (NSFWとついてるカテゴリーはNSFWチャンネルでのみ見れます。)
        ```
        普通 - normal
        問題 - question
        癒し - cute
        二次元 - 2d, NSFW
        CG (2.5次元) - cg, NSFW
        三次元 - 3d, NSFW
        ```

        !lang en
        --------
        Sorry, English is Not supported yet."""
        if not ctx.invoked_subcommand:
            await self.show(
                ctx, self.MODES[
                    "nsfw" if getattr(
                        ctx.channel, "nsfw", False
                    ) else "normal"
                ][0]
            )

    def get_mode(self, mode: str) -> str:
        return self.ALIASES.get(mode, mode)

    @funp.command(
        aliases=["see", "sw", "しょう", "見る"],
        description="Funpをランダムで取り出して表示します。"
    )
    async def show(self, ctx, mode: str = MODE_OPTION):
        """!lang ja
        --------
        Funpを表示します。  
        カテゴリーの指定をしない場合は`rf!funp`でも表示はできます。

        Parameters
        ----------
        mode : カテゴリー
            閲覧する画像のカテゴリーです。

        Warnings
        --------
        NSFWカテゴリーにはあなたを不快にさせたりする画像がある可能性があります。  
        それともし誰かのいたずらによりモラルやdiscord利用規約に反する画像が出てきた場合はサポートサーバーまでお知らせください。  
        以上の理由から実行は自己責任となります。ご注意ください。"""
        mode = self.get_mode(mode)
        if mode in self.MODES["nsfw"] and not getattr(ctx.channel, "nsfw", False):
            await ctx.reply(
                {"ja": "nsfwのカテゴリーはnsfwチャンネルでのみ表示可能です。",
                 "en": "You can see NSFW funp image in only NSFW Channel."}
            )
        elif any(mode in self.MODES[key] for key in self.MODES):
            try:
                row = await self.read(mode)
            except IndexError:
                await ctx.reply(
                    {"ja": "まだ登録されていません。",
                     "en": "まだ登録されていません。"}
                )
            else:
                embed = discord.Embed(
                    title=f"Funp - {row[1]}",
                    description=(
                        f'投稿者：{getattr(self.bot.get_user(row[0]), "name", row[0])}'
                        f" (`{row[0]}`)"
                    ),
                    color=self.bot.colors["normal"]
                )
                embed.set_image(url=row[2])

                await ctx.reply(
                    embed=embed, view=warn_view
                )
        else:
            await ctx.reply(
                {"ja": "カテゴリーが存在しません。",
                 "en": "The category is not found."}
            )

    NAME_OPTION = discord.SlashOption("name", "画像の名前です。")

    @funp.command(
        aliases=["new", "ad", "あどど", "追加"],
        description="Funpを追加します。※スラッシュコマンドでは使えません。"
    )
    async def add(self, ctx, mode: str = MODE_OPTION, name: str = NAME_OPTION):
        """!lang ja
        --------
        Funpに画像を追加します。  
        対応フォーマット一覧：`png, jpg, jpeg, gif`

        Parameters
        ----------
        mode : カテゴリー
            一番上に載せているカテゴリーです。
        name : str
            画像名です。

        Examples
        --------
        Funp登録動画例：[YouTube](https://youtu.be/IiKGMiIUD8g)

        Warnigns
        --------
        NSFWカテゴリーではないカテゴリーにNSFWの画像を乗せた場合はすぐ削除してください。  
        もしNSFWカテゴリーに載せて放置した場合はその画像を見つけた人があなたを通報します。  
        -> RTを使用できなくなるなどの何かしらのペナルティが課せられる可能性があります。"""
        mode = self.get_mode(mode)
        if ctx.message.attachments:
            if ctx.message.attachments[0].filename.lower().endswith(
                    ("png", "jpg", "jpeg", "gif")
                ):
                await self.write(
                    ctx.author.id, name,
                    ctx.message.attachments[0].url, mode
                )
                await ctx.reply("Ok")
            else:
                await ctx.reply(
                    {"ja": "その画像フォーマットは対応していません。",
                     "en": "That picture format is not supported."}
                )
        else:
            await ctx.reply(
                {"ja": "画像を添付してください。",
                 "en": "Please attach picture."}
            )

    @funp.command(
        aliases=["rm", "delete", "del", "りむーぶ", "削除"],
        description="Funpを削除します。"
    )
    async def remove(
        self, ctx, mode: str = MODE_OPTION, name: str = NAME_OPTION,
        user_id: int = discord.SlashOption(
            "id", "対象のユーザーIDです。(管理者のみ)", required=False,
            default=None
        )
    ):
        """!lang ja
        --------
        登録したFunpを削除します。

        Parameters
        ----------
        mode : カテゴリー
            Funpの画像のカテゴリーです。
        name : str
            Funpの画像の名前です。
        user_id : int, optional
            そのFunpの登録者です。  
            指定しない場合は実行者が登録者としてコマンドが実行されます。  
            この引数はRTの管理者のみ指定可能です。"""
        mode = self.get_mode(mode)
        if user_id and ctx.author.id not in self.bot.owner_ids:
            return await ctx.reply(
                "Error, ユーザーID指定は管理者のみです。"
            )
        user_id = user_id or ctx.author.id
        try:
            await self.delete(user_id, name, mode)
        except KeyError:
            await ctx.reply(
                {"ja": "そのFunpが見つかりませんでした。",
                 "en": "The funp is not found."}
            )
        else:
            await ctx.reply("Ok")

    @funp.command(
        "list", description="自分の登録したFunpの一覧を見ることができます。"
    )
    @commands.cooldown(1, 5, commands.BucketType.user)
    async def _list(
        self, ctx, mode: str = MODE_OPTION,
        user_id: int = discord.SlashOption(
            "id", "対象のユーザーIDです。(管理者のみ)", required=False,
            default=None
        )
    ):
        """!lang ja
        --------
        自分の登録したFunpのリストをカテゴリ別に見ます。
        
        Parameters
        ----------
        mode : カテゴリー
            見たい画像のカテゴリーです。
        user_id : int, optional
            そのFunpの登録者です。
            指定しなかった場合は実行者が登録者として扱われます。
            管理者のみこの引数を指定できます。"""
        mode = self.get_mode(mode)
        if user_id and ctx.author.id not in self.bot.owner_ids:
            return await ctx.reply(
                "Error, ユーザーID指定は管理者のみです。"
            )
        user_id = user_id or ctx.author.id
        try:
            li = await self.get_list(user_id)
        except KeyError:
            return await ctx.reply(
                {"ja":"まだFunpはありません。",
                 "en":"There is no Funp."}
            )
        else:
            embed = discord.Embed(
                title="Funp一覧",
                desdcription="\n".join([f"[{m[1]}]({m[2]})" for m in li])
            )

    @funp.command(
        aliases=["nb"], description="NekoBot APIを使用してNSFWな画像を表示します。"
    )
    @commands.cooldown(1, 5, commands.BucketType.user)
    async def nekobot(
            self, ctx, type_: str = discord.SlashOption(
                "type", "NSFWの種類です。", choices={
                    "hentai": "hentai",
                    "nakadashi": "nakadashi",
                    "paizuri": "paizuri",
                    "tentacle": "tentacle",
                    "boobs": "boobs"
                }
            )
        ):
        """!lang ja
        --------
        NekoBot APIを利用したNSFW画像を表示するコマンドです。  
        NSFWチャンネルでのみ実行が可能です。"""
        if ctx.channel.nsfw:
            async with self.bot.session.get(
                f"https://nekobot.xyz/api/image?type={type_}"
            ) as r:
                data = await r.json()
                if data["success"]:
                    embed = discord.Embed(
                        title="NekoBot - " + type_,
                        color=data["color"]
                    )
                    embed.set_image(url=data["message"])
                    embed.set_footer(text="Powered by NekoBot API")
                    await ctx.reply(embed=embed)
                else:
                    await ctx.reply(
                        ("Error! 種類があっているか確認してください。"
                         f"Message:`{data['message']}`")
                    )
        else:
            await ctx.reply(
                {"ja": "NSFWチャンネルのみ有効です。",
                 "en": "Only nsfw channel."}
            )


def setup(bot):
    bot.add_cog(Funp(bot))
