# Free RT - Role Linker

from __future__ import annotations

from typing import Optional

from collections import defaultdict

from discord.ext import commands
import discord

from util import RT, Table


class RoleLinkerData(Table):
    __allocation__ = "GuildID"
    data: dict[str, tuple[int, bool]]  # OriginalRoleID: (RoleID, Reverse)


class DataManager:

    DB = "RoleLinker"

    def __init__(self, bot: RT):
        self.data = RoleLinkerData(bot)

    def _prepare(self, guild_id: int) -> None:
        # セーブデータの準備をする。
        if "data" not in self.data[guild_id]:
            self.data[guild_id].data = {}

    def write(
        self, guild_id: int, original_role_id: int,
        role_id: int, reverse: bool = False
    ) -> None:
        "ロールリンクを設定します。"
        self.data[guild_id].data[str(original_role_id)] = (role_id, reverse)

    def delete(self, guild_id: int, original_role_id: int) -> None:
        "ロールリンクを削除します。"
        self._prepare(guild_id)
        if (original_role_id := str(original_role_id)) in self.data[guild_id].data:
            del self.data[guild_id].data[original_role_id]
        else:
            raise KeyError("そのロールリンクは見つかりませんでした。")

    def read(self, guild_id: int, original_role_id: int) -> Optional[tuple[int, bool]]:
        "ロールリンクのデータを読み込みます。"
        self._prepare(guild_id)
        if (original_role_id := str(original_role_id)) in self.data[guild_id].data:
            return self.data[guild_id].data[original_role_id]

    def get_all(self, guild_id: int) -> list[tuple[int, int, int, bool]]:
        "全てのロールリンクのデータを取得します。"
        self._prepare(guild_id)
        return [(guild_id, int(orid)) + tuple(row) for orid, row in self.data[guild_id].data.items()]


class RoleLinker(commands.Cog, DataManager):
    def __init__(self, bot: RT):
        self.bot = bot
        self.running: dict[int, list[int]] = defaultdict(list)
        super(commands.Cog, self).__init__(self.bot)

    @commands.group(
        extras={
            "headding": {
                "ja": "ロールリンカー, 役職が付与/削除された際に他も付与/削除するようにする機能",
                "en": "Role linker, Ability to grant/delete other positions when they are granted/deleted."
            }, "parent": "ServerUseful"
        }
    )
    async def linker(self, ctx):
        """!lang ja
        --------
        ロールリンカー、役職が付与/削除された際に他の役職も付与/削除するようにする機能です。  
        認証機能にて複数の役職を付与するようにしたい際に使えます。  
        `rf!linker`と実行することで登録されてるロールリンクの一覧を表示できます。

        !lang en
        --------
        Ability to grant/delete other positions when they are granted/deleted.  
        It can be use when you want set captcha role multiple.
        You can do `rf!linker` to see role link that registerd list."""
        if not ctx.invoked_subcommand:
            await ctx.reply(
                embed=discord.Embed(
                    title={
                        "ja": "ロールリンクリスト",
                        "en": "Role link list"
                    },
                    description="\n".join(
                        f"<@&{row[1]}>：<@&{row[2]}>\n　リバース：{'on' if row[3] else 'off'}"
                        for row in self.get_all(ctx.guild.id)
                    ),
                    color=self.bot.colors["normal"]
                )
            )

    @linker.command()
    async def link(self, ctx, target: discord.Role, link_role: discord.Role, reverse: bool = False):
        """!lang ja
        --------
        ロールリンクを設定します。  
        15個まで登録可能です。

        Parameters
        ----------
        target : 役職のメンションまたは名前
            リンク対象の役職です。
        link_role : 役職のメンションまたは名前
            リンクする役職です。
        reverse : bool, default off
            役職が付与されたら指定したlink_roleを剥奪する、というように通常の逆にするかどうかです。  
            onまたはoffを入れます。

        Examples
        --------
        `rf!linker link 認証済み メンバー`
        認証済みの役職がついたらメンバーという役職をつけます。

        Notes
        -----
        reverseをonにする際、既に1つでもロールリンカーに登録されている役職を対象に設定することは出来ません。  
        理由は大量のつけ外しを行うことによってRTにAPI制限がかかることを防ぐためです。ご了承ください。

        !lang en
        --------
        Sets the job title link.
        You can register up to 10 of them.

        Parameters
        ----------
        target : Mention or name of the position
            The role that triggers the grant or drop of the role.
        link_role : Mention or name of the role
            The role to be granted or removed when target is granted or removed.
        reverse : bool, default off
            Whether or not to reverse the normal behavior, such as stripping the specified link_role when a role is granted.  
            Can be on or off.

        Examples
        --------
        `rf!linker link authenticated member`.
        If the role is authenticated, it will be given the role "member".

        Notes
        -----
        If reverse is on, you cannot set the target role to a role that is already registered with the role linker.  
        The reason is that if you don't do this, you can create loops and interfere with RT. Thank you for your understanding."""
        if len(self.get_all(ctx.guild.id)) == 15:
            await ctx.reply(
                {"ja": "これ以上リンクすることはできません。",
                 "en": "No more links can be made."}
            )
        else:
            try:
                self.write(
                    ctx.guild.id, target.id, link_role.id, reverse
                )
            except ValueError:
                await ctx.reply(
                    {"ja": "既にロールリンカーに登録されている役職を設定することはできません。",
                     "en": "You can't set the target role to a role that is already registered."}
                )
            else:
                await ctx.reply("Ok")

    @linker.command()
    async def unlink(self, ctx, target: discord.Role):
        """!lang ja
        --------
        linkの逆です。  
        ロールリンクを解除します。

        Parameters
        ----------
        target : 役職のメンションまたは名前
            役職リンクに設定されている役職です。

        !lang en
        --------
        The opposite of link.  
        Removes the position link.

        Parameters
        ----------
        target : Mention or name of the position
            The position set in the position link."""
        try:
            self.delete(ctx.guild.id, target.id)
        except KeyError:
            await ctx.reply(
                {"ja": "そのロールリンクが見つかりませんでした。",
                 "en": "That role link is not found."}
            )
        else:
            await ctx.reply("Ok")

    async def role_update(
        self, mode: str, role: discord.Role, member: discord.Member,
        did: Optional[list[int]] = None
    ) -> None:
        "ロールの置き換えをする"
        did = did or []
        if member.id not in self.running[member.guild.id]:
            self.running[member.guild.id].append(member.id)
        if row := self.read(member.guild.id, role.id):
            if link_role := member.guild.get_role(row[0]):
                role, add = member.get_role(row[0]), None
                if mode == "add":
                    if not row[1] and not role:
                        add = True
                    elif row[1] and role:
                        add = False
                elif mode == "remove":
                    if not row[1] and role:
                        add = False
                    elif row[1] and not role:
                        add = True

                if add is not None:
                    do = True
                    if add:
                        if link_role.id in did:
                            # 繰り返しを検知したらストップする。
                            do = False
                        else:
                            did.append(link_role.id)
                    if do:
                        await (
                            member.add_roles if add else member.remove_roles
                        )(link_role)
                        return await self.role_update(
                            "add" if add else "remove", link_role, member, did
                        )
        if member.id in self.running[member.guild.id]:
            self.running[member.guild.id].remove(member.id)

    @commands.Cog.listener()
    async def on_member_update(self, before, after):
        if self.bot.is_ready():
            for role in before.roles:
                if not after.get_role(role.id) and role.name != "@everyone":
                    # もしロールが削除されたなら。
                    self.bot.dispatch("role_remove", role, after)
                    if after.id not in self.running[after.guild.id]:
                        await self.role_update("remove", role, after)
            for role in after.roles:
                if not before.get_role(role.id) and role.name != "@everyone":
                    # もしロールが追加されたなら。
                    self.bot.dispatch("role_add", role, after)
                    if after.id not in self.running[after.guild.id]:
                        await self.role_update("add", role, after)


def setup(bot):
    bot.add_cog(RoleLinker(bot))
