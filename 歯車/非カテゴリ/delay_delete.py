# Free RT - Delay Delete Message

from discord.ext import commands, tasks
import discord

from rtlib import RT, DatabaseManager, setting
from time import time


class DataManager(DatabaseManager):

    DB = "DelayDelete"

    def __init__(self, db, maxsize: int = 160):
        self.db = db
        self._maxsize = maxsize

    async def init_table(self, cursor) -> None:
        await cursor.create_table(
            self.DB, {
                "ChannelID": "BIGINT", "MessageID": "BIGINT",
                "DeleteTime": "BIGINT"
            }
        )

    async def _gets(self, cursor, channel_id: int) -> list:
        await cursor.cursor.execute(
            """SELECT * FROM {}
                WHERE ChannelID = %s
                ORDER BY MessageID DESC;""".format(self.DB),
            (channel_id,)
        )
        return await cursor.cursor.fetchall()

    async def write(self, cursor, channel_id: int, message_id: int, delay: int) -> None:
        target = {"ChannelID": channel_id}
        delete_target = target
        if len(rows := await self._gets(cursor, channel_id)) >= self._maxsize:
            delete_target["MessageID"] = rows[-1][1]
            await cursor.delete(self.DB, delete_target)
        delete_target["MessageID"] = message_id
        delete_target["DeleteTime"] = int(time() + delay)
        await cursor.insert_data(self.DB, delete_target)

    async def reads(self, cursor) -> list:
        return [row async for row in cursor.get_datas(self.DB, {})
                if row]

    async def delete(self, cursor, channel_id: int, message_id: int) -> None:
        target = {"ChannelID": channel_id, "MessageID": message_id}
        if await cursor.exists(self.DB, target):
            await cursor.delete(self.DB, target)


class DelayDelete(commands.Cog, DataManager):
    def __init__(self, bot: RT):
        self.bot = bot
        self.bot.loop.create_task(self.init_database())

    async def init_database(self):
        super(commands.Cog, self).__init__(self.bot.mysql)
        await self.init_table()
        self.delete_loop.start()

    @commands.command(
        aliases=["dd", "遅延削除"], extras={
            "headding": {"ja": "遅延削除メッセージ", "en": "Delay Delete Message"},
            "parent": "ServerTool"
        }
    )
    @commands.cooldown(1, 30, commands.BucketType.channel)
    @setting.Setting("guild", "DelayDeleteMessage", channel=discord.TextChannel)
    async def delaydelete(self, ctx, minutes: int, *, content):
        """!lang ja
        --------
        遅延削除機能です。  
        作成したメッセージを指定した期間だけたったら削除します。

        Parameters
        ----------
        minutes : int
            何分後にメッセージを削除するか。
        content : str
            何のメッセージを送るか。

        Notes
        -----
        指定したチャンネル内に送られたメッセージを指定された期間だけたったら削除ということもできます。  
        使いたい場合は対象のチャンネルのトピックに`rf>delaydelete 何分後削除するか`を入れましょう。

        Warnings
        --------
        この機能で遅延削除するメッセージは最大160個まで覚えます。  
        それ以上遅延削除するメッセージを登録した場合最後に登録された遅延削除対象メッセージが削除されなくなります。  
        悪用防止のためです。ご了承ください。

        Aliases
        -------
        dd, 遅延削除

        !lang en
        --------
        Delayed deletion function.  
        This function deletes the created message after a specified period of time.

        Parameters
        ----------
        minutes : int
            The number of minutes after which the message will be deleted.
        content : str
            What message to send.

        Notes
        -----
        Similar to this function, you can delete messages sent to a specified channel after a specified time.  
        To use this feature, send `rf>delaydelete minutes later` to the topic in the target channel.

        Warnings
        --------
        This function can remember up to 160 messages to be delayed deleted.  
        If you register more than 160 messages for delayed deletion, the last message registered for delayed deletion will not be deleted.  
        This is to prevent misuse. Thank you for your understanding.

        Aliases
        -------
        dd, Delayed deletion"""
        new = await ctx.channel.webhook_send(
            username=ctx.author.display_name,
            avatar_url=getattr(ctx.author.avatar, "url", None),
            wait=True, content=content.replace("@", "＠")
        )
        await self.write(ctx.channel.id, new.id, 60 * minutes)
        await ctx.message.delete()

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if (not message.guild or message.author.bot
                or isinstance(message.channel, discord.Thread)
                or not message.channel.topic):
            return

        for line in message.channel.topic.splitlines():
            if line.startswith("rf>delaydelete "):
                try:
                    await self.write(
                        message.channel.id, message.id,
                        60 * int(line.replace("rf>delaydelete ", ""))
                    )
                except ValueError:
                    await message.reply(
                        "このチャンネルのトピックの`rf>delaydelete`の使い方が間違っています。"
                    )

    def cog_unload(self):
        self.delete_loop.cancel()

    @tasks.loop(seconds=30)
    async def delete_loop(self):
        now = time()
        for row in await self.reads():
            if row[-1] <= now:
                channel = self.bot.get_channel(row[0])
                if channel:
                    try:
                        message = await channel.fetch_message(row[1])
                        await message.delete()
                    except Exception as e:
                        if self.bot.test:
                            print("Error on Delay Delete:", e)
                await self.delete(row[0], row[1])


def setup(bot):
    bot.add_cog(DelayDelete(bot))
