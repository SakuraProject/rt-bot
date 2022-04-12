# Free RT - Auto Role

from discord.ext import commands
import discord

from rtlib import DatabaseManager, setting


class DataManager(DatabaseManager):

    DB = "AutoRole"

    def __init__(self, db):
        self.db = db

    async def init_table(self, cursor) -> None:
        await cursor.create_table(
            self.DB, {
                "GuildID": "BIGINT", "Role": "BIGINT"
            }
        )

    async def write(self, cursor, guild_id: int, role_id: int) -> None:
        target, change = {"GuildID": guild_id}, {"Role": role_id}
        if await cursor.exists(self.DB, target):
            await cursor.update_data(self.DB, change, target)
        else:
            target.update(change)
            await cursor.insert_data(self.DB, target)

    async def read(self, cursor, guild_id: int) -> tuple:
        target = {"GuildID": guild_id}
        if await cursor.exists(self.DB, target):
            return await cursor.get_data(self.DB, target)
        return ()

    async def delete(self, cursor, guild_id: int) -> None:
        target = {"GuildID": guild_id}
        await cursor.delete(self.DB, target)


class AutoRole(commands.Cog, DataManager):
    def __init__(self, bot):
        self.bot = bot
        self.bot.loop.create_task(self.prepare_database())

    async def prepare_database(self):
        super(commands.Cog, self).__init__(self.bot.mysql)
        await self.init_table()

    @commands.command(
        aliases=["are", "自動役職", "オートロール", "おーとろーる"], extras={
            "headding": {
                "ja": "サーバーに誰かが参加した際に指定された役職を自動で付与します。",
                "en": "Automatically assigns a role to a user when he or she joins the server."
            }, "parent": "ServerTool"
        }
    )
    @commands.cooldown(1, 10, commands.BucketType.guild)
    @commands.has_guild_permissions(administrator=True)
    @setting.Setting("guild", "AutoRole")
    async def autorole(self, ctx, onoff: bool, *, role: discord.Role = None):
        """!lang ja
        --------
        ユーザーがサーバーに参加した際に自動で役職を付与します。

        Parameters
        ----------
        onoff : bool
            この設定を有効にする場合はonで無効にするならoffを入力します。
        role : 役職の名前かメンション
            サーバーに誰かが参加した際に何の役職を付与するかです。  
            もしonoffをoffにした場合はこれは入力しなくて良いです。

        Examples
        --------
        `rf!autorole on 初心者`

        Aliases
        -------
        are, 自動役職, オートロール, おーとろーる

        !lang en
        --------
        Automatically assigns a role to a user when he or she joins the server.

        Parameters
        ----------
        onoff : bool
            Enter "on" to enable this setting, or "off" to disable it.
        role : The name of the role or a mention.
            When someone joins the server, what role will be assigned to them.  
            If you set onoff to off, you don't need to enter this.

        Examples
        --------
        `rf!autorole on beginner`.

        Aliases
        -------
        are"""
        if onoff:
            if role:
                await self.write(ctx.guild.id, role.id)
                await ctx.reply("Ok")
            else:
                await ctx.reply(
                    {"ja": "設定をONにする場合は役職を指定してください。",
                     "en": "If you want to set auto role, you must specify role to command."}
                )
        else:
            await self.delete(ctx.guild.id)
            await ctx.reply("Ok")

    @commands.Cog.listener()
    async def on_member_join(self, member):
        row = await self.read(member.guild.id)
        if row:
            if (role := member.guild.get_role(row[1])):
                try:
                    await member.add_roles(role)
                except discord.Forbidden:
                    pass
            else:
                await self.delete(member.guild.id)


def setup(bot):
    bot.add_cog(AutoRole(bot))
