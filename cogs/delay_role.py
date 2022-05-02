# Free RT - Delay Role

from __future__ import annotations

from typing import Optional

from time import time

from discord.ext import commands, tasks
import discord

from aiomysql import Pool, Cursor

from util import RT, Cacher
from util import DatabaseManager


class DataManager(DatabaseManager):
    def __init__(self, pool: Pool):
        self.pool = pool
        self.pool._loop.create_task(self._prepare_table())

    async def _prepare_table(self, cursor: Cursor = None):
        await cursor.execute(
            """CREATE TABLE IF NOT EXISTS DelayRole (
                GuildID BIGINT, RoleID BIGINT PRIMARY KEY NOT NULL,
                DelayTime BIGINT
            );"""
        )

    async def write(
        self, guild_id: int, role_id: int, delay: Optional[int] = None,
        cursor: Cursor = None
    ) -> None:
        "DelayRoleの設定を書き込みます。"
        if delay is None:
            try:
                await cursor.execute(
                    "DELETE FROM DelayRole WHERE GuildID = %s AND RoleID = %s;",
                    (guild_id, role_id)
                )
            except Exception as e:
                assert False, {
                    "ja": f"エラーが発生しました。\nCode: `{e}`\n設定が既にない可能性があります。",
                    "en": f"Error has occurred.\nCode: `{e}`\nThe setting may not already be there."
                }
        else:
            assert len(await self.read(guild_id, cursor)) < 10, {
                "ja": "これ以上設定できません。", "en": "No further settings are possible."
            }
            await cursor.execute(
                """INSERT INTO DelayRole VALUES (%s, %s, %s)
                    ON DUPLICATE KEY UPDATE DelayTime = %s;""",
                (guild_id, role_id, delay, delay)
            )

    async def delete(self, guild_id: int, cursor: Cursor = None) -> None:
        "指定されたサーバーのDelayRoleの設定を全て削除します。"
        await cursor.execute(
            "DELETE FROM DelayRole WHERE GuildID = %s;", (guild_id,)
        )

    async def read(self, guild_id: int, cursor: Cursor = None) -> list[tuple[int, int]]:
        "DelayRoleの設定を読み込みます。"
        await cursor.execute(
            "SELECT RoleID, DelayTime FROM DelayRole WHERE GuildID = %s;", guild_id
        )
        return [row for row in await cursor.fetchall() if row]

    async def reads(self, cursor: Cursor = None) -> list[tuple[int, int, int]]:
        "DelayRoleの設定を全サーバー全て取得します。"
        await cursor.execute("SELECT * FROM DelayRole;")
        return await cursor.fetchall()


class DelayRole(commands.Cog, DataManager):
    def __init__(self, bot: RT):
        self.bot = bot
        self.recently: Cacher[int, list[int]] = self.bot.cachers.acquire(60.0, list)
        super(commands.Cog, self).__init__(self.bot.mysql.pool)
        self.check_queue_deadline.start()

    @commands.group(
        aliases=("dr", "遅延ロール", "ちろ"), extras={
            "headding": {"ja": "遅延ロール自動付与機能", "en": "Automatic delayed roll assignment function"},
            "parent": "ServerTool"
        }
    )
    async def delayRole(self, ctx: commands.Context):
        """!lang ja
        --------
        遅延ロール自動付与機能です。
        サーバーに入室したメンバーに、ロールを自動付与する機能である`autorole`の、遅延バージョンです。
        これは何秒後のようにしてロールを付与することができます。

        Warnings
        --------
        この機能は関係ない人にもロールが付与されることがあります。
        (この関係ない人は、既に遅延時間を超えていない人は含まれません)
        「メンバー入室時に、そのメンバーをロール付与の対象としてセーブデータに書き込み、しばらくした後に、そのセーブデータに書き込まれているメンバーにロールを付与する。」
        というような仕組みではなく「定期的に、メンバー全員をチェックする。チェック内容は、現在の時間とメンバーの入室時間の差が、遅延時間より多いかどうかです。もし多い場合は、そのメンバーにロールを付与する。」という仕組みとなっています。
        セーブデータが肥大化するのを避けるための解決方法です。
        ご了承ください。

        Aliases
        -------
        dr, 遅延ロール, ちろ

        !lang en
        --------
        Delayed role auto-granting function.
        This is a delayed version of `autorole`, a function that automatically grants roles to members who enter the server.
        Roles can be granted after a certain number of seconds.

        Warnings
        --------
        This feature may also grant roles to unrelated people.
        (These unrelated people do not include those who have not already exceeded the delay time.)
        "When a member enters a server, the member is written into the saved data as a role grantee, and a short time later, the role is granted to the member whose saved data is being written into the saved data."
        Instead of such a mechanism, "Periodically, all members are checked. The check is whether the difference between the current time and the member's entry time is more than the delay time. If it is more, the member is given a role." This is how the system works.
        This is a solution to avoid save data bloat.
        Please understand this.

        Aliases
        -------
        dr"""
        if not ctx.invoked_subcommand:
            await ctx.reply({
                "ja": "使用方法が違います。", "en": "This is a wrong way to use this command."
            })

    @delayRole.command(aliases=("l", "一覧"))
    async def list(self, ctx: commands.Context):
        """!lang ja
        --------
        設定一覧を表示します。

        Aliases
        -------
        l, 一覧

        !lang en
        --------
        Displays tehe list of setting.

        Aliases
        -------
        l"""
        await ctx.reply(embed=discord.Embed(
            title=self.__cog_name__,
            description="\n".join(
                f"<@&{role_id}>：{delay}"
                for role_id, delay in await self.read(ctx.guild.id)
            ), color=self.bot.Colors.normal
        ))

    @delayRole.command(aliases=("s", "設定"))
    @commands.has_guild_permissions(manage_roles=True)
    async def set(self, ctx: commands.Context, delay: int, *, role: discord.Role):
        """!lang ja
        --------
        遅延ロールを設定します。

        Parameters
        ----------
        delay : int
            何秒遅延するかです。
            もし日付等で指定したい場合は`rf!calc 式`で計算ができるのでそれを使ったりして秒数に計算してください。
            三十五秒以下にすると大幅に付与が遅れます。
        role : ロールの名前かメンションまたはID
            付与するロールです。

        Notes
        -----
        設定できる最大の数は10個です。

        Aliases
        -------
        s, 設定

        !lang en
        --------
        Sets the delay role.

        Parameters
        ----------
        delay : int
            The number of seconds to delay.
            If you want to specify a date, you can use `rf!calc expression` to calculate the number of seconds.
            If it is less than 35 seconds, the grant is significantly delayed.
        role : role name, mentions or ID
            The role to be granted.

        Notes
        -----
        The maximum number that can be set is 10.

        Aliases
        -------
        s"""
        await ctx.trigger_typing()
        await self.write(ctx.guild.id, role.id, delay)
        await ctx.reply("Ok")

    @delayRole.command(aliases=("del", "d", "削除"))
    @commands.has_guild_permissions(manage_roles=True)
    async def delete(self, ctx: commands.Context, *, role: discord.Role):
        """!lang ja
        --------
        遅延ロール設定を削除します。

        Parameters
        ----------
        role : ロールのメンションか名前またはID
            削除する設定のロールです。

        Aliases
        -------
        del, d, 削除

        !lang en
        --------
        Deletes the delayed role setting.

        Parameters
        ----------
        role : Mention or name or ID of the role
            The role of the configuration to be deleted.

        Aliases
        -------
        del, d"""
        await ctx.trigger_typing()
        await self.write(ctx.guild.id, role.id, None)
        await ctx.reply("Ok")

    @tasks.loop(seconds=30)
    async def check_queue_deadline(self):
        # キューの処理を行います。
        now, guild = time(), None
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                for guild_id, role_id, delay in await self.reads(cursor):
                    if guild is None:
                        guild = self.bot.get_guild(guild_id)
                    # もしサーバーが見つからないのなら設定を削除する。
                    if guild is None:
                        await self.delete(guild_id, cursor)
                        continue
                    # もしロールが見つからないのなら設定を削除する。
                    if (role := guild.get_role(role_id)) is None:
                        await self.write(guild_id, role_id, None, cursor)

                    # ロール付与対象を探しロールを付与する。
                    for member in guild.members:
                        if not member.bot and member.get_role(role_id) is None \
                                and now - member.joined_at.timestamp() > delay:
                            # もしメンバーが参加後しばらく経過していてロール付与対象の場合はロールを付与する。
                            try: 
                                await member.add_roles(role)
                            except Exception:
                                ...
                    guild = None

    def cog_unload(self):
        self.check_queue_deadline.cancel()


async def setup(bot):
    await bot.add_cog(DelayRole(bot))
