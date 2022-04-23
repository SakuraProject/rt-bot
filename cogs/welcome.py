# Free RT - Welocme Message

from typing import Literal

from discord.ext import commands
import discord

from util.mysql_manager import DatabaseManager
from util import RT, settings
from asyncio import sleep


class DataManager(DatabaseManager):

    DB = "Welcome"

    def __init__(self, db):
        self.db = db

    async def init_table(self, cursor) -> None:
        await cursor.create_table(
            self.DB, {
                "GuildID": "BIGINT", "ChannelID": "BIGINT",
                "Content": "TEXT", "Mode": "TEXT"
            }
        )

    async def write(
        self, cursor, guild_id: int, channel_id: int,
        content: str, mode: str
    ) -> None:
        target = {"GuildID": guild_id, "Mode": mode}
        change = {"ChannelID": channel_id, "Content": content}
        if await cursor.exists(self.DB, target):
            await cursor.update_data(self.DB, change, target)
        else:
            target.update(change)
            await cursor.insert_data(self.DB, target)

    async def delete(self, cursor, guild_id: int, mode: str) -> None:
        target = {"GuildID": guild_id, "Mode": mode}
        if await cursor.exists(self.DB, target):
            await cursor.delete(self.DB, target)
        else:
            raise KeyError("そのサーバーは設定していません。")

    async def read(self, cursor, guild_id: int, mode: str) -> tuple:
        target = {"GuildID": guild_id, "Mode": mode}
        if await cursor.exists(self.DB, target):
            return await cursor.get_data(self.DB, target)
        else:
            return ()


class Welcome(commands.Cog, DataManager):
    def __init__(self, bot: RT):
        self.bot = bot
        self.bot.loop.create_task(self.on_ready())

    async def on_ready(self):
        super(commands.Cog, self).__init__(self.bot.mysql)
        await self.init_table()

    @commands.command(
        aliases=["wm", "ようこそ"], extras={
            "headding": {
                "ja": "ウェルカムメッセージ",
                "en": "Welcome message"
            }, "parent": "ServerTool"
        }
    )
    @commands.cooldown(1, 8, commands.BucketType.guild)
    @commands.has_guild_permissions(administrator=True)
    async def welcome(self, ctx, mode: Literal["join", "remove"], *, content):
        """!lang ja
        --------
        ウェルカムメッセージを設定します。    
        このコマンドを実行したチャンネルにメンバーがサーバーに参加した際に指定したメッセージが送信されるようになります。  
        また退出時に送信するメッセージも設定できます。

        Parameters
        ----------
        mode : str
            参加時に送信するメッセージを設定する場合は`join`を、退出時に送信するメッセージを設定するなら`remove`を入力します。
        content : str
            ウェルカムメッセージの内容です。  
            オフにする場合はこれを`off`にしてください。

        Notes
        -----
        以下の三つをメッセージ内に置けばそれに対応するものにメッセージ送信時に置き換えます。  
        これを使えば`XX人目の参加者です！`のようなメッセージを作ることができます。
        ```
        $ment$ 参加者のメンション
        $name$ 参加者の名前
        $count$ サーバーにいる人の人数
        ```

        Examples
        --------
        ```
        rf!welcome join $ment$, ようこそ！RTサーバーへ！！
        あなたは$count$人目の参加者です。
        ```

        Aliases
        -------
        wm, ようこそ

        !lang en
        --------
        Sets the welcome message.  
        When a member joins the server on the channel where this command is executed, the specified message will be sent.  
        You can also set a message to be sent when you leave the room.

        Parameters
        ----------
        mode : str
            Enter `join` to set a message to be sent when you join, or `remove` to set a message to be sent when you leave.
        content : str
            The content of the welcome message.  
            If you want to turn it off, set it to `off`.

        Notes
        -----
        If you put the following three in your message, it will be replaced by the corresponding one when you send the message.  
        You can use this to create a message like `You are the XXth person to join! You can use this to create a message such as:
        ````
        $ment$ Participant's Mention
        $name$ Participant's name
        $count$ Number of people on the server.
        ```

        Examples
        --------
        ```
        rf!welcome join $ment$, Welcome to the RT server!
        You are the $count$th participant.
        Welcome to the RT server!
        ```

        Aliases
        -------
        wm"""
        if mode in ("join", "remove"):
            if content.lower() in ("off", "false", "disable", "0"):
                try:
                    await self.delete(ctx.guild.id, mode)
                except KeyError:
                    await ctx.reply(
                        {"ja": "まだ設定されていません。",
                        "en": "Welcome has not set yet."}
                    )
                else:
                    await ctx.reply("Ok")
            else:
                await self.write(ctx.guild.id, ctx.channel.id, content, mode)
                await ctx.reply("Ok")
        else:
            await ctx.reply(
                {"ja": "モードは参加時の`join`と退出時の`remove`のみが使用できます。",
                 "en": "The only modes available are `join` for joining and `remove` for leaving."}
            )

    async def on_member_join_remove(self, mode: str, member: discord.Member):
        if self.bot.is_ready():
            if (row := await self.read(member.guild.id, mode)):
                row[2] = (row[2]
                    .replace("$ment$", member.mention)
                    .replace("$name$", member.name)
                    .replace("$count$", str(len(member.guild.members))))
                channel = member.guild.get_channel(row[1])
                if channel:
                    await sleep(3)
                    await channel.send(row[2])

    @commands.Cog.listener()
    async def on_member_join(self, member):
        await self.on_member_join_remove("join", member)

    @commands.Cog.listener()
    async def on_member_remove(self, member):
        await self.on_member_join_remove("remove", member)


def setup(bot):
    bot.add_cog(Welcome(bot))
