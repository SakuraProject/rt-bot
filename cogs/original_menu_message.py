# Free RT - Original Menu Message

from typing import Callable, Coroutine

from discord.ext import commands
import discord

from util.mysql_manager import DatabaseManager
from time import time


class DataManager(DatabaseManager):

    MAX_SIZE = 30

    def __init__(self, db, maxsize: int = MAX_SIZE):
        self.db = db
        self.maxsize = maxsize

    async def init_table(self, cursor) -> None:
        await cursor.create_table(
            "originalMenu", {
                "GuildID": "BIGINT", "ChannelID": "BIGINT",
                "MessageID": "BIGINT", "Data": "JSON",
                "RegTime": "BIGINT"
            }
        )

    async def write(
            self, cursor, guild_id: int, channel_id: int,
            message_id: int, data: dict) -> None:
        await cursor.cursor.execute(
            """SELECT * FROM originalMenu
                WHERE GuildID = %s
                ORDER BY RegTime DESC;""",
            (guild_id,)
        )
        if len(rows := await cursor.cursor.fetchall()) == self.maxsize:
            # もし十個作っているなら最初に作ったやつを消す。
            await cursor.delete(
                "originalMenu", {
                    "GuildID": rows[-1][0], "ChannelID": rows[-1][1],
                    "MessageID": rows[-1][2]
                }
            )
        await cursor.insert_data(
            "originalMenu", {
                "GuildID": guild_id, "ChannelID": channel_id,
                "MessageID": message_id, "data": data,
                "RegTime": int(time())
            }
        )

    async def read(
        self, cursor, guild_id: int, channel_id: int,
            message_id: int) -> tuple:
        target = {
            "GuildID": guild_id, "ChannelID": channel_id,
            "MessageID": message_id
        }
        if await cursor.exists("originalMenu", target):
            if (row := await cursor.get_data("originalMenu", target)):
                return row
        raise KeyError("そのメニューメッセージは見つかりませんでした。")


CUSTOM_ID = "OriginalMenuMessage"


class MenuView(discord.ui.View):
    def __init__(
        self, bot_id: int, on_interaction: Callable[
            [discord.Interaction], Coroutine
        ], *args, **kwargs
    ):
        self.bot_id, self.on_interaction = bot_id, on_interaction
        kwargs["timeout"] = kwargs.get("kwargs", None)
        super().__init__(*args, **kwargs)

    async def _on_interaction(self, interaction):
        if interaction.message.author.id == self.bot_id:
            return await self.on_interaction(interaction)

    @discord.ui.button(emoji="?", custom_id=f"{CUSTOM_ID}DashLeft")
    async def dash_left(self, _, interaction):
        await self._on_interaction(interaction)

    @discord.ui.button(emoji="??", custom_id=f"{CUSTOM_ID}Left")
    async def left(self, _, interaction):
        await self._on_interaction(interaction)

    @discord.ui.button(emoji="??", custom_id=f"{CUSTOM_ID}Right")
    async def right(self, _, interaction):
        await self._on_interaction(interaction)

    @discord.ui.button(emoji="?", custom_id=f"{CUSTOM_ID}DashRight")
    async def dash_right(self, _, interaction):
        await self._on_interaction(interaction)


class OriginalMenuMessage(commands.Cog, DataManager):
    def __init__(self, bot):
        self.bot = bot
        self.bot.loop.create_task(self.on_ready())
        self.view = MenuView(self.bot.user.id, self.on_interaction)
        self.bot.add_view(self.view)

    async def on_ready(self):
        super(commands.Cog, self).__init__(self.bot.mysql)
        await self.init_table()

    def make_embed(self, color: discord.Color, data: list) -> discord.Embed:
        return discord.Embed(
            title=data[0], description=data[1],
            color=color
        )

    @commands.command(
        aliases=["embeds", "メニュー", "めにゅー"],
        extras={
            "headding": {
                "ja": "メニューメッセージ",
                "en": "Menu message"
            }, "parent": "ServerPanel"
        }
    )
    @commands.has_permissions(manage_messages=True)
    async def menu(self, ctx: commands.Context, *, content):
        """!lang ja
        --------
        矢印ボタンで操作可能なメニューメッセージを作ります。  
        一つのサーバーにつき三十個まで作成可能です。  
        **もし三十一個以上作った場合は古いものから無効になります。**

        Parameters
        ----------
        content : str
            メニューに入れる文字列です。  
            下の例のように、`$タイトル`のようにメニューのページのタイトルを設定して、その次の行にそのページの説明を書きます。  
            もしメッセージに入れきれないほど書く場合はテキストファイルに書き込み、この引数を`file`と書いてそのテキストファイルを添付してコマンドを実行してください。  
            テキストファイルにすればメニューメッセージを作り直す際に楽になります。

        Examples
        --------
        ```
        rf!menu $質問をする前に 1ページ目
        自分でGoogleなどである程度調べてわからない債に質問してください。
        $質問をする前に 2ページ目
        敬語を使って質問しましょう。
        $質問をする前に 3ページ目
        質問をしないように自分でできるようにしましょう。
        ```

        !lang en
        --------
        Creates a menu message that can be operated by arrow buttons.  
        Up to 30 can be created per server.  
        **If you make 31, the first one will be invalid.**

        Parameters
        ----------
        content: str
            The string to menu.  
            Set the title of the page in the menu, as in `$ Title`, followed by a description of the page.  
            If you're not sure, look at the example below.  
            If you write more than you can fit in a message, write it in a text file and run the command with this argument as `file`.  
            If you write it in a text file, it will be easier to recreate it.

        Examples
        --------
        ```
        rf!menu $Before asking questions, page one.
        Ask yourself questions about bonds that you don't know by doing some research on Google.
        $Before I ask you a question, page two.
        Let's ask questions using honorific expressions.
        $Before I ask you a question, page three.
        Try not to ask questions and do it yourself.
        ```"""
        if content == "file":
            if ctx.message.attachments:
                at = ctx.message.attachments[0]
                if at.filename.endswith(".txt") and at.size <= 1500000:
                    content = (await at.read()).decode()
                else:
                    return await ctx.reply(
                        {"ja": "ファイル形式は`txt`にしてください。\nまたはファイルサイズが巨大すぎます。",
                         "en": "The file type must be `txt`. Or the file size so big that I can't recieve it."}
                    )
            else:
                return await ctx.reply(
                    {"ja": "ファイルがアップロードされていません。",
                     "en": "The file has not been uploaded."}
                )
        page, data = 0, {}
        for content in content.split("$"):
            if content:
                page += 1
                data[str(page)] = [
                    content[:(index := content.find("\n"))],
                    content[index:]
                ]

        if data:
            message = await ctx.send(
                content=f"1/{len(data)}",
                embed=self.make_embed(ctx.author.color, data["1"]),
                view=self.view
            )
            await self.write(
                ctx.guild.id, ctx.channel.id, message.id, data
            )
        else:
            await ctx.reply(
                {"ja": "内容がないので作れません。",
                 "en": "I can't make message because content is nothing."}
            )

    async def on_button_pushed(self, mode, interaction):
        try:
            row = await self.read(
                interaction.guild.id, interaction.channel.id,
                interaction.message.id
            )
        except KeyError:
            pass
        else:
            index = interaction.message.content.find("/")
            if index == -1:
                content = interaction.message.content
            else:
                content = interaction.message.content[index + 1:]
            index = str(
                (
                    1 if mode.endswith("Left")
                    else interaction.message.content[index + 1:]
                ) if mode.startswith("Dash") else (
                    int(
                        interaction.message.content[:1 if index == -1 else index]
                    ) + (-1 if mode == "Left" else 1)
                )
            )
            content = (
                index if content == interaction.message.content
                else f"{index}/{content}"
            )

            if (data := row[3].get(index)):
                await interaction.response.edit_message(
                    content=content, embed=self.make_embed(
                        interaction.message.embeds[0].color, data
                    )
                )
            else:
                await interaction.response.send_message(
                    content="これ以上ページを切り替えられません。", ephemeral=True
                )

    async def on_interaction(self, interaction: discord.Interaction):
        await self.on_button_pushed(
            interaction.data["custom_id"].replace(CUSTOM_ID, ""), interaction
        )


async def setup(bot):
    await bot.add_cog(OriginalMenuMessage(bot))
