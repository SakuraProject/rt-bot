# Free RT - Locker

from discord.ext import commands, tasks
import discord

from util import mysql
from util.mysql_manager import DatabaseManager
from typing import List
from time import time


class DataManager(DatabaseManager):
    def __init__(self, db):
        self.db: mysql.MySQLManager = db

    async def init_table(self, cursor):
        await cursor.create_table(
            "Locker", {"ChannelID": "BIGINT", "Time": "BIGINT"}
        )

    async def save(self, cursor, channel_id: int, time_: int) -> None:
        target = {"ChannelID": channel_id}
        if not await cursor.exists("Locker", target):
            target["Time"] = time_
            await cursor.insert_data("Locker", target)

    async def delete(self, cursor, channel_id: int) -> None:
        target = {"ChannelID": channel_id}
        if await cursor.exists("Locker", target):
            await cursor.delete("Locker", target)

    async def exists(self, cursor, channel_id: int) -> None:
        return await cursor.exists("Locker", {"ChannelID": channel_id})

    async def loads(self, cursor) -> list:
        return [row async for row in cursor.get_datas("Locker", {})]


class Locker(commands.Cog, DataManager):
    def __init__(self, bot):
        self.bot = bot

    async def cog_load(self):
        super(commands.Cog, self).__init__(
            self.bot.mysql
        )
        await self.init_table()
        self.auto_unlock_loop.start()

    async def channel_lock(
        self, channel: discord.TextChannel, lock: bool,
        roles: List[discord.Role] = []
    ) -> List[discord.Role]:
        "指定されたチャンネルをロックします。"
        cans, lock = [], not lock
        if not channel.overwrites:
            overwrites = {
                channel.guild.default_role: discord.PermissionOverwrite(
                    send_messages=lock
                )
            }
            cans.append(channel.guild.default_role)
            await channel.edit(overwrites=overwrites)

        reason = "アンロック" if lock else "ロック"

        for roles in (channel.overwrites, roles):
            for role in roles:
                if len(channel.overwrites) != 1 and role.name == "@everyone":
                    continue
                perms = channel.overwrites_for(role)
                perms.send_messages = lock
                cans.append(role)
                await channel.set_permissions(
                    role, overwrite=perms, reason=reason
                )

        return cans

    def make_result_embed(self, title: dict, roles: List[discord.Role]) -> discord.Embed:
        return discord.Embed(
            title=title,
            description=", ".join(role.mention for role in roles),
            color=self.bot.colors["normal"]
        )

    @commands.command(name="lock", extras={
        "headding": {"ja": "チャンネルのロックです。", "en": "Lock channel."},
        "parent": "ServerTool"
    })
    @commands.has_permissions(manage_channels=True)
    @commands.cooldown(1, 300, commands.BucketType.channel)
    async def lock_(self, ctx, *, auto_unload: int = 0):
        """!lang ja
        --------
        チャンネルをロックして権限を持っている人しか喋れないようにします。

        Parameters
        ----------
        auto_unlock : int, default 0
            何分後に自動解除をするかです。  
            デフォルトは0で自動解除をしません。  
            例えば5を入れれば五分後に権限を持っていない人も喋れるようになります。

        !lang en
        --------
        Lock channel.

        Parameters
        ----------
        auto_unlock : int, default 0
            The number of minutes after which RT will automatically unlock.
            The default is 0, which means no automatic unlocking.
            For example, a value of 5 will keep it locked for five minutes."""
        await ctx.typing()
        time_ = time() + auto_unload * 60 if auto_unload else 0
        if time_ and not await self.exists(ctx.channel.id):
            await self.save(ctx.channel.id, time_)
        await ctx.reply(
            embed=self.make_result_embed(
                {"ja": "ロックしました。", "en": "I have locked."},
                roles=await self.channel_lock(ctx.channel, True)
            )
        )

    @commands.command(extras={
        "headding": {"ja": "チャンネルのロック解除です。", "en": "Unlock channel."},
        "parent": "ServerTool"
    })
    @commands.has_permissions(manage_channels=True)
    @commands.cooldown(1, 300, commands.BucketType.channel)
    async def unlock(self, ctx):
        """!lang ja
        --------
        チャンネルのロックを解除します。

        See Also
        --------
        lock : チャンネルをロックします。

        !lang en
        --------
        Unlock channel.

        See Also
        --------
        lock : Lock channel."""
        await ctx.typing()
        if await self.exists(ctx.channel.id):
            await self.delete(ctx.channel.id)
        await ctx.reply(
            embed=self.make_result_embed(
                {"ja": "アンロックしました。", "en": "I have unlocked."},
                roles=await self.channel_lock(ctx.channel, False)
            )
        )

    def cog_unload(self):
        self.auto_unlock_loop.cancel()

    @tasks.loop(seconds=30)
    async def auto_unlock_loop(self):
        # 自動で解除するように設定されているものを解除する。
        now = time()
        for row in await self.loads():
            if row:
                channel = self.bot.get_channel(row[0])
                if channel:
                    if row[1] <= now:
                        await self.channel_lock(channel, False)
                    else:
                        continue
                await self.delete(channel.id)


async def setup(bot):
    await bot.add_cog(Locker(bot))
