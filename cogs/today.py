# Free RT - What day is today

from discord.ext import commands, tasks
import discord

from util.mysql_manager import DatabaseManager
from bs4 import BeautifulSoup
from datetime import datetime, timedelta


class DataManager(DatabaseManager):

    DB = "Today"

    def __init__(self, db):
        self.db = db

    async def init_table(self, cursor) -> None:
        await cursor.create_table(
            self.DB, {
                "GuildID": "BIGINT", "ChannelID": "BIGINT"
            }
        )

    async def write(self, cursor, guild_id: int, channel_id: int) -> None:
        target = {
            "GuildID": guild_id, "ChannelID": channel_id
        }
        if await cursor.exists(self.DB, target):
            raise KeyError("既に設定されています。")
        else:
            await cursor.insert_data(self.DB, target)

    async def delete(self, cursor, guild_id: int, channel_id: int) -> None:
        await cursor.delete(
            self.DB, {"GuildID": guild_id, "ChannelID": channel_id}
        )

    async def reads(self, cursor, guild_id: int = None) -> list:
        target = {}
        if guild_id is not None:
            target["GuildID"] = guild_id
        return [
            row async for row in cursor.get_datas(
                self.DB, target)
            if row
        ]


class Today(commands.Cog, DataManager):

    YAHOO_ICON = "http://www.google.com/s2/favicons?domain=www.yahoo.co.jp"

    def __init__(self, bot):
        self.bot = bot
        self.yet = True

    async def cog_load(self):
        await self.bot.wait_until_ready()
        super(commands.Cog, self).__init__(self.bot.mysql)
        await self.init_table()
        self.today_notification.start()

    async def get_today(self) -> discord.Embed:
        # 今日はなんの日をyahooから持ってくる。
        async with self.bot.session.get(
            "https://kids.yahoo.co.jp/today"
        ) as r:
            day = BeautifulSoup(
                await r.read(), "html.parser"
            ).find("dl")

            embed = discord.Embed(
                title=day.find("span").text,
                description=day.find("dd").text,
                color=0xee373e
            )
            embed.set_footer(
                text="Yahoo きっず",
                icon_url=self.YAHOO_ICON
            )
        return embed

    @commands.command(
        extras={
            "headding": {
                "ja": "「今日は何の日」を表示、通知します。",
                "en": "Sorry, This command is not supported."
            }, "parent": "Entertainment"
        }
    )
    @commands.cooldown(1, 10, commands.BucketType.guild)
    async def today(self, ctx, setting: bool = None):
        """!lang ja
        --------
        「今日は何の日」を表示または通知します。

        Parameters
        ----------
        setting : bool, default False
            通知を設定するかどうかです。  
            onにすると実行したチャンネルに毎日午前9時に通知を送るように設定をします。  
            offにすると通知をオフにしてその日の分の「今日は何の日」を表示します。  
            デフォルトはoffです。

        Examples
        --------
        `rf!today` 「今日は何の日」を表示します。
        `rf!today on` 実行したチャンネルに毎日午前9時に「今日は何の日」を送信します。"""
        if setting is None:
            await ctx.reply(embed=await self.get_today())
        elif ctx.author.guild_permissions.manage_channels:
            try:
                await self.write(ctx.guild.id, ctx.channel.id)
                if len(await self.reads(ctx.guild.id)) == 4:
                    raise OverflowError(
                        "一つのサーバーにつき三つまでしか設定できないようにする。"
                    )
            except (KeyError, OverflowError) as e:
                await self.delete(ctx.guild.id, ctx.channel.id)
                if isinstance(e, OverflowError):
                    return await ctx.reply(
                        "一つのサーバーにつき四つまで設定が可能です。"
                    )
            await ctx.reply("Ok")
        else:
            await ctx.reply("チャンネル管理権限がないと通知の設定はできません。")

    def cog_unload(self):
        self.today_notification.cancel()

    @tasks.loop(seconds=30)
    async def today_notification(self):
        # 今日はなんの日通知をする。
        if self.yet and (
            datetime.now() + timedelta(hours=9)
        ).strftime("%H:%M") == "09:00":
            for row in await self.reads():
                channel = self.bot.get_channel(row[1])
                if channel:
                    try:
                        await channel.send(embed=await self.get_today())
                    except (discord.HTTPException, discord.Forbidden):
                        pass
                else:
                    # もしチャンネルが見つからないなら設定を削除する。
                    await self.delete(row[0], row[1])
            self.yet = False
        else:
            self.yet = True


async def setup(bot):
    await bot.add_cog(Today(bot))
