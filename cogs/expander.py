# Free RT - Message Link Expander

from typing import Literal

from discord.ext import commands
import discord

from util import RT
from util.mysql_manager import DatabaseManager

from re import findall


class DataManager(DatabaseManager):

    DB = "ExpandMessage"
    IGNORE_DB = "ExpandIgnore"

    def __init__(self, db):
        self.db = db

    async def init_table(self, cursor) -> None:
        await cursor.create_table(
            self.DB, {
                "GuildID": "BIGINT", "OnOff": "TINYINT"
            }
        )
        await cursor.create_table(
            self.IGNORE_DB, {"ChannelID": "BIGINT", "OnOff": "TINYINT"}
        )

    async def read(self, cursor, guild_id: int, channel_id: int) -> tuple:
        target = {"GuildID": guild_id}
        ignore_target = {"ChannelID": channel_id}
        if await cursor.exists(self.DB, target):
            if (guild := await cursor.get_data(self.DB, target))[1]:
                if await cursor.exists(self.IGNORE_DB, ignore_target):
                    if (row := await cursor.get_data(self.IGNORE_DB, ignore_target)):
                        return bool(row[1])
                    return False
                else:
                    return guild[1]
            return False
        else:
            return True

    async def write(self, cursor, guild_id: int, onoff: bool) -> None:
        target = {"GuildID": guild_id}
        change = {"OnOff": int(onoff)}
        if await cursor.exists(self.DB, target):
            await cursor.update_data(self.DB, change, target)
        else:
            target.update(change)
            await cursor.insert_data(self.DB, target)

    async def set_ignore(self, cursor, channel_id: int, onoff: bool) -> None:
        target = {"ChannelID": channel_id}
        change = {"OnOff": int(onoff)}
        if await cursor.exists(self.IGNORE_DB, target):
            await cursor.update_data(self.IGNORE_DB, change, target)
        else:
            target.update(change)
            await cursor.insert_data(self.IGNORE_DB, target)


class Expander(commands.Cog, DataManager):

    PATTERN = (
        "https://(ptb.|canary.)?discord(app)?.com/channels/"
        "(?P<guild>[0-9]{18})/(?P<channel>[0-9]{18})/(?P<message>[0-9]{18})"
    )

    def __init__(self, bot: RT):
        self.bot = bot

    async def cog_load(self):
        await self.bot.wait_until_ready()
        super(commands.Cog, self).__init__(
            self.bot.mysql
        )
        await self.init_table()

    @commands.command(
        extras={
            "headding": {
                "ja": "メッセージリンク展開 on/off", "en": "message link expansion on/off"
            }, "parent": "ServerUseful"
        }
    )
    @commands.has_guild_permissions(administrator=True)
    async def expand(self, ctx, onoff: bool, mode: Literal["g"] = "g"):
        """!lang ja
        --------
        メッセージリンクの展開のオンオフの切り替えコマンドです。  
        指定したチャンネルではメッセージリンクを展開しないなどの設定もできます。  
        デフォルトはオンです。

        Parameters
        ----------
        onoff : bool
            onまたはoffです。
        mode : str, default g
            サーバーでの設定かチャンネルでの設定かです。  
            もしこれをg以外にすると実行したチャンネルにonoffが設定されます。  
            例えばこの機能がOnの状態で問い合わせチャンネルで`rf!expand off c`と実行すれば問い合わせチャンネルのみメッセージリンクが展開されなくなります。

        Examples
        --------
        `rf!expand off` デフォルトでOnなのでリンク展開されたくない方はこれを実行しましょう。

        !lang en
        --------
        This command toggles the message link expansion on and off.  
        This command can also be used to disable message link expansion for a specified channel.  
        This function is On by default.

        Parameters
        ----------
        onoff : bool
            On or off.
        mode : str, default g
            Either the server or the channel setting.  
            If this is not g, onoff will be set on the channel where it is executed.  
            For example, if this feature is on and you run `rf!expand off c` on a query channel, only the query channel will not expand message links.

        Examples
        --------
        If you don't need this feature, you can use `rf!expand off`, which is on by default."""
        if mode == "g":
            await self.write(ctx.guild.id, onoff)
        else:
            await self.set_ignore(ctx.channel.id, onoff)
        await ctx.reply("Ok")

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if not message.guild or message.author.bot:
            return

        datas = findall(self.PATTERN, message.content)
        if datas:
            if await self.read(message.guild.id, message.channel.id):
                embeds = []
                for data in datas:
                    data, channel = data[2:], None

                    if data[0] == str(message.guild.id):
                        get_channel = message.guild.get_channel
                    elif data[1] == str(message.channel.id):
                        channel = message.channel
                    else:
                        get_channel = self.bot.get_channel
                    if channel is None:
                        channel = get_channel(int(data[1]))

                    if channel:
                        try:
                            fetched_message = await channel.fetch_message(int(data[2]))
                        except discord.Forbidden:
                            await message.add_reaction(
                                self.bot.cogs["TTS"].EMOJIS["error"]
                            )
                        else:
                            embed = discord.Embed(
                                description=fetched_message.content,
                                color=fetched_message.author.color
                            ).set_author(
                                name=fetched_message.author.display_name,
                                icon_url=getattr(fetched_message.author.display_avatar, "url", "")
                            ).set_footer(
                                text=fetched_message.guild.name,
                                icon_url=getattr(fetched_message.guild.icon, "url", "")
                            )
                            if fetched_message.attachments:
                                embed.set_image(url=fetched_message.attachments[0].url)
                            embeds.append(embed)

                if embeds:
                    if fetched_message.content:
                        await self.send(message, embeds)
                    if fetched_message.embeds:
                        await self.send(message, fetched_message.embeds)

    async def send(self, message: discord.Message, embeds: list[discord.Embed]):
        try:
            if hasattr(message.channel, "topic"):
                await message.channel.webhook_send(
                    username=message.author.display_name,
                    avatar_url=getattr(message.author.display_avatar, "url", ""),
                    content=message.clean_content, embeds=embeds
                )
                await message.delete()
            else:
                # スレッドの場合は普通に送信をする。
                for embed in embeds:
                    await message.channel.send(embed=embed)
        except (discord.HTTPException, discord.NotFound):
            ...


async def setup(bot):
    await bot.add_cog(Expander(bot))
