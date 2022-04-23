# Free RT - Channel Status

from discord.ext import commands, tasks
import discord

from util import RT
from util.mysql_manager import DatabaseManager


class DataManager(DatabaseManager):
    def __init__(self, db):
        self.db = db

    async def init_table(self, cursor) -> None:
        await cursor.create_table(
            "channelStatus", {
                "GuildID": "BIGINT", "ChannelID": "BIGINT",
                "Text": "TEXT"
            }
        )

    async def load(self, cursor, guild_id: int) -> list:
        await cursor.cursor.execute(
            "SELECT * FROM channelStatus WHERE GuildID = %s;", (guild_id,)
        )
        return await cursor.cursor.fetchall()

    async def load_all(self, cursor) -> list:
        await cursor.cursor.execute("SELECT * FROM channelStatus;")
        return await cursor.cursor.fetchall()

    async def save(self, cursor, guild_id: int, channel_id: int, text: str) -> None:
        target = {"GuildID": guild_id, "ChannelID": channel_id}
        change = {"Text": text}
        if await cursor.exists("channelStatus", target):
            await cursor.update_data("channelStatus", change, target)
        else:
            target.update(change)
            await cursor.insert_data("channelStatus", target)

    async def delete(self, cursor, guild_id: int, channel_id: int) -> None:
        target = {"GuildID": guild_id, "ChannelID": channel_id}
        if await cursor.exists("channelStatus", target):
            await cursor.delete("channelStatus", target)


class ChannelStatus(commands.Cog, DataManager):
    def __init__(self, bot: RT):
        self.bot = bot
        self.bot.loop.create_task(self.on_ready())

    async def on_ready(self):
        super(commands.Cog, self).__init__(
            self.bot.mysql
        )
        await self.init_table()
        self.status_updater.start()

    @commands.command(extras={
        "headding": {
            "ja": "チャンネルにメンバー数などを表示する。",
            "en": "Displays the number of members and other information in the channel name."
        }, "parent": "ServerUseful"
    })
    @commands.has_guild_permissions(manage_channels=True)
    async def status(self, ctx, *, text):
        """!lang ja
        --------
        テキストチャンネルの名前を指定したものに固定します。  
        5分ごとに更新され、メンバー数などの変数を利用するとステータスのようになります。  
        実行したチャンネルに設定されます。

        Parameters
        ----------
        text : 文字列またはオフにする際はoff
            チャンネル名に表示するものです。  
            下のメモにあるものを置くことで自動でそれに対応するメンバー数などに置き換わります。

        Notes
        -----
        ```
        !ch! テキストチャンネル数
        !mb! メンバー数 (Botを含める。)
        !bt! Bot数
        !us! ユーザー数 (Botを含めない。)
        ```

        Examples
        --------
        `rf!status メンバー数：!mb!`

        !lang en
        --------
        Displays the number of members and other information in a text channel.  
        This will be set to the channel that was executed.

        Parameters
        ----------
        text : string or off to turn off
            This is what will be displayed in the channel name.  
            If you put something in the notes below, it will be automatically replaced with the corresponding number of members, etc.

        Notes
        -----
        ```
        !ch! Text channel count.
        !mb! Member Count (Including Bot Count)
        !bt! Bot Count
        !us! User Count (Not including Bot Count)
        ```

        Examples
        --------
        `rf!status Members:!mb!`"""
        if text.lower() in ("false", "off", "disable", "0"):
            await self.delete(ctx.guild.id, ctx.channel.id)
            content = {"ja": "", "en": ""}
        else:
            await self.save(ctx.guild.id, ctx.channel.id, text)
            content = {
                "ja": "\n※五分に一回ステータスを更新するのでしばらくステータス更新に時間がかかる可能性があります。",
                "en": "\n※Status update will late because RT will update status displayed in the channel every five minutes."
            }
        await ctx.reply(
            {"ja": f"設定しました。{content['ja']}",
             "en": f"I have set.{content['en']}"}
        )

    def cog_unload(self):
        self.status_updater.cancel()

    def replace_text(self, template: str, guild: discord.Guild) -> str:
        # テンプレートにあるものを情報に交換する。
        text = template.replace("!ch!", str(len(guild.text_channels)))
        text = text.replace("!mb!", str(len(guild.members)))
        if "!us!" in template or "!bt!" in template:
            bots, users = [], []
            for member in guild.members:
                if member.bot:
                    bots.append(member)
                else:
                    users.append(member)
            text = text.replace("!bt!", str(len(bots)))
            text = text.replace("!us!", str(len(users)))
        return text

    @tasks.loop(minutes=5)
    async def status_updater(self):
        for _, channel_id, text in await self.load_all():
            channel = self.bot.get_channel(channel_id)
            if channel:
                if channel.name != (
                        text := self.replace_text(text, channel.guild)
                    ):
                    try:
                        await channel.edit(
                            name=text, reason="ステータス更新のため。/To update status."
                        )
                    except Exception as e:
                        self._last_exception = e


def setup(bot):
    bot.add_cog(ChannelStatus(bot))
