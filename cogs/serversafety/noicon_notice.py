# Free RT - No Icon Notice

from typing import Optional

from discord.ext import commands
import discord

from aiomysql import Pool, Cursor

from util import DatabaseManager
from util import RT


class DataManager(DatabaseManager):

    TABLE = "NoIconNotice"

    def __init__(self, pool: Pool):
        self.pool = pool
        pool._loop.create_task(self._prepare_table())

    async def _prepare_table(self, cursor: Cursor = None):
        await cursor.execute(
            f"""CREATE TABLE IF NOT EXISTS {self.TABLE} (
                GuildID BIGINT PRIMARY KEY NOT NULL, Text TEXT
            );"""
        )

    async def write(self, guild_id: int, text: str, cursor: Cursor = None) -> None:
        "書き込みをします。もし空の文字列が渡された場合はデータを消します。"
        if text:
            await cursor.execute(
                f"""INSERT INTO {self.TABLE} VALUES (%s, %s)
                    ON DUPLICATE KEY UPDATE Text = %s;""",
                (guild_id, text, text)
            )
        else:
            assert (await self._read(cursor, guild_id)) is not None, {
                "ja": "既に設定がありません。", "en": "Already deleted"
            }
            await cursor.execute(
                f"DELETE FROM {self.TABLE} WHERE GuildID = %s;",
                (guild_id,)
            )

    async def _read(self, cursor, guild_id: int) -> Optional[str]:
        await cursor.execute(
            f"SELECT Text FROM {self.TABLE} WHERE GuildID = %s;", (guild_id,)
        )
        if row := await cursor.fetchone():
            return row[0]

    async def read(self, guild_id: int, cursor: Cursor = None) -> Optional[str]:
        "読み込みをします。"
        return await self._read(cursor, guild_id)


class NoIconNotice(commands.Cog, DataManager):
    def __init__(self, bot: RT):
        self.bot = bot
        super(commands.Cog, self).__init__(self.bot.mysql.pool)

    @commands.command(aliases=("nin", "アイコン無し通知"), extras={
        "headding": {"ja": "アイコン未設定ユーザーに警告", "en": "Notice to user unset icon"},
        "parent": "ServerSafety"
    })
    @commands.has_guild_permissions(administrator=True)
    @commands.cooldown(1, 10, commands.BucketType.guild)
    async def noinotice(self, ctx, *, text=""):
        """!lang ja
        -------
        アイコンを設定していない人がサーバーに参加した際に、指定したメッセージをその人のDMに送信します。

        Parameters
        ----------
        text : str, default ""
            送信する文字列です。
            もし何も入力しなかった場合は機能をオフにします。

        Aliases
        -------
        nin, アイコン無し通知

        !lang en
        --------
        When a person who has not set an icon joins the server, the specified message is sent to that person's DM.

        Parameters
        ----------
        text : str, default ""
            The string to be sent.
            If nothing is entered it will be interpreted as off.

        Aliases
        -------
        nin"""
        await ctx.typing()
        assert len(text) < 1500, {
            "ja": "文章は1500文字以内である必要があります。",
            "en": "Text must be no more than 1500 characters."
        }
        await self.write(ctx.guild.id, text)
        await ctx.reply("Ok")

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member):
        if member.avatar is None:
            if text := await self.read(member.guild.id):
                await member.send(f"**Notice from {member.guild.name}：**\n{text}")


async def setup(bot):
    await bot.add_cog(NoIconNotice(bot))
