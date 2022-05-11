# Free RT - Delay Lottery

from discord.ext import commands, tasks
import discord

from util import RT
from util.mysql_manager import DatabaseManager
from time import time


class DataManager(DatabaseManager):

    DB = "DelayLottery"

    def __init__(self, db, maxsize=30):
        self.db = db
        self.maxsize = maxsize

    async def init_table(self, cursor) -> None:
        await cursor.create_table(
            self.DB, {
                "GuildID": "BIGINT", "Date": "BIGINT",
                "ChannelID": "BIGINT", "MessageID": "BIGINT"
            }
        )

    async def write(
        self, cursor, guild_id: int, date: int,
        channel_id: int, message_id: int
    ) -> None:
        target = {"GuildID": guild_id}
        change = {"Date": date, "ChannelID": channel_id, "MessageID": message_id}
        if len(
            [row async for row in cursor.get_datas(self.DB, target)
             if row]
        ) < self.maxsize:
            target.update(change)
            await cursor.insert_data(self.DB, target)
        else:
            raise OverflowError("追加しすぎです。")

    async def delete(
        self, cursor, guild_id: int, channel_id: int, message_id: int
    ) -> None:
        target = {
            "GuildID": guild_id, "ChannelID": channel_id,
            "MessageID": message_id
        }
        if await cursor.exists(self.DB, target):
            await cursor.delete(self.DB, target)

    async def delete_guild(self, cursor, guild_id: int) -> None:
        await cursor.delete(self.DB, {"GuildID": guild_id})

    async def reads(self, cursor) -> dict:
        data = {}
        async for row in cursor.get_datas(self.DB, {}):
            if row:
                if row[0] not in data:
                    data[row[0]] = []
                data[row[0]].append(row[1:])
        return data


class DelayLottery(commands.Cog, DataManager):

    EMOJIS = {
        "check": "<:check_mark:885714065106808864>",
        "error": "<:error:878914351338246165>"
    }

    def __init__(self, bot: RT):
        self.bot = bot

    async def cog_load(self):
        super(commands.Cog, self).__init__(self.bot.mysql)
        await self.init_table()
        self.lottery_worker.start()

    @commands.command(
        aliases=["dl", "期限抽選"], extras={
            "headding": {
                "ja": "抽選パネル", "en": "Lottery Panel"
            }, "parent": "ServerPanel"
        }
    )
    @commands.cooldown(1, 30, commands.BucketType.channel)
    async def dlottery(self, ctx, count: int, minutes: int, *, description):
        """!lang ja
        --------
        時間制限を付けて、リアクションをした人の中から抽選をするパネルを作ります。

        Notes
        -----
        この機能は実行した際に抽選を行う`lottery`コマンドの進化版のようなものです。  
        一つのサーバーにつき同時に30個まで作ることができ、もし抽選をやめる場合はバツのリアクションを押してください。  

        Parameters
        ----------
        count : int
            抽選で選ぶ人の人数です。
        minutes : int
            何分後に抽選を行うか。
        title : str
            パネルのタイトルです。
        descriptiopn : str
            パネルの説明です。

        Examples
        --------
        ```
        rt!dlottery 3 180 RTサーバー導入数750記念
        記念のNitro抽選で三時間以内に下のチェックリアクションを押した人の中で三人にNitroをあげます！
        ```

        Aliases
        -------
        dl, 期限抽選

        !lang en
        --------
        Create a panel to draw lots from among those who react.

        Notes
        -----
        It is a kind of evolution of the `lottery` command.
        You can create up to 30 of these per server, and if you don't want to do the lottery, just press the "Batsu" reaction.

        Parameters
        ----------
        count : int
            The number of people to be selected by lottery.
        minutes : int
            After how many minutes will the lottery be held?
        title : str
            The title of the panel.
        descriptiopn : str
            Explanation of the panel.

        Examples
        --------
        ```
        rt!dlottery 3 180 RT server installation 750th anniversary
        I'll give three Nitros to the three people who press the check reaction button below within three hours of the memorial Nitro drawing!
        ```

        Aliases
        -------
        dl"""
        title = description[:(index := description.find("\n"))]
        description = description[index:]
        mes = await ctx.channel.webhook_send(
            username=ctx.author.display_name + f" - {ctx.author.id}",
            avatar_url=getattr(ctx.author.display_avatar, "url", ""),
            content=str(count), embed=discord.Embed(
                title=title, description=description, color=ctx.author.color
            ), wait=True
        )
        try:
            await self.write(
                mes.guild.id, int(time() + 60 * minutes),
                mes.channel.id, mes.id
            )
        except OverflowError:
            await ctx.reply(
                {"ja": "数が大きすぎてオーバーフローしました。",
                 "en": "The number is too many to overflow."}
            )
            await mes.delete()
        else:
            for emoji in self.EMOJIS.values():
                await mes.add_reaction(emoji)

    @tasks.loop(seconds=31)
    async def lottery_worker(self):
        now = time()
        for guild_id, rows in (await self.reads()).items():
            guild = self.bot.get_guild(guild_id)
            if guild:
                for row in rows:
                    if row[0] < now:
                        if (channel := guild.get_channel(row[1])):
                            try:
                                message = await channel.fetch_message(row[2])
                            except discord.NotFound:
                                continue
                            if message.reactions:
                                members = (await message.reactions[0].users().flatten())[1:]
                                await self.bot.cogs["ServerTool"].lottery(
                                    await self.bot.get_context(message),
                                    (length if (c := int(message.content)) > (length := len(members)) else c),
                                    target=members
                                )
                    else:
                        continue
                    await self.delete(guild_id, row[1], row[2])
            else:
                await self.delete_guild(guild_id)

    @commands.Cog.listener()
    async def on_full_reaction_add(self, payload):
        if (not hasattr(payload, "message") or not payload.message.guild
                or not payload.message.author.bot):
            return

        if (str(payload.emoji) == self.EMOJIS["error"]
                and str(payload.user_id) in payload.message.author.name):
            await self.delete(
                payload.guild_id, payload.channel_id, payload.message_id
            )
            await payload.message.delete()
            await payload.message.channel.send(
                f"{payload.member.mention}, 抽選をキャンセルしました。 / Canceled!"
            )

    def cog_unload(self):
        self.lottery_worker.cancel()


async def setup(bot):
    await bot.add_cog(DelayLottery(bot))
