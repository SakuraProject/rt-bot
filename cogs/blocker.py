# Free RT - Blocker

from __future__ import annotations

from typing import Union, Literal

from collections import defaultdict
from collections.abc import Iterator

from discord.ext import commands
import discord

from aiomysql import Pool, Cursor
from ujson import loads, dumps

from util import DatabaseManager
from util import RT

from .automod.modutils import emoji_count


class DataManager(DatabaseManager):

    TABLE = "Blocker"
    Mode = Literal["emoji", "stamp", "reaction"]
    cache: dict[int, dict[Mode, list[int]]] = {}
    MAX_ROLES = 15

    def __init__(self, cog: "Blocker"):
        self.cog = cog
        self.pool: Pool = self.cog.bot.mysql.pool
        self.cog.bot.loop.create_task(self.prepare_table())

    async def prepare_table(self, cursor: Cursor = None) -> None:
        """テーブルの準備をします。クラスのインスタンス化時に自動で実行されます。
        また、クラスにキャッシュを作成します。"""
        await cursor.execute(
            f"""CREATE TABLE IF NOT EXISTS {self.TABLE} (
                GuildID BIGINT, Mode TEXT, Targets JSON
            );"""
        )
        await self.update_cache(cursor=cursor)

    async def update_cache(self, cursor: Cursor = None) -> None:
        "キャッシュをアップデートします。"
        self.cache = defaultdict(lambda: defaultdict(list))
        await cursor.execute(f"SELECT * FROM {self.TABLE};")
        for row in await cursor.fetchall():
            if row:
                self.cache[row[0]][row[1]] = loads(row[2])

    async def write(self, guild_id: int, mode: Mode, cursor: Cursor = None) -> bool:
        "設定をします。"
        if guild_id in self.cache and mode in self.cache[guild_id]:
            await cursor.execute(
                f"DELETE FROM {self.TABLE} WHERE GuildID = %s AND Mode = %s;",
                (guild_id, mode)
            )
            del self.cache[guild_id][mode]
            return False
        else:
            await cursor.execute(
                f"INSERT INTO {self.TABLE} VALUES (%s, %s, %s);",
                (guild_id, mode, "[]")
            )
            self.cache[guild_id][mode] = []
            return True

    def assert_blocker(self, guild_id: int, mode: Mode) -> None:
        "設定がされているかどうかのAssertionを行います。"
        assert guild_id in self.cache and mode in self.cache[guild_id], \
            "まだ設定がされていません。"

    async def _update(self, cursor, guild_id, mode, data):
        await cursor.execute(
            f"""UPDATE {self.TABLE} SET Targets = %s
                WHERE GuildID = %s AND Mode = %s;""",
            (dumps(data), guild_id, mode)
        )

    async def add_role(
        self, guild_id: int, mode: Mode, role: int, cursor: Cursor = None
    ) -> None:
        "ブロック対象のロールを追加します。"
        self.assert_blocker(guild_id, mode)
        self.cache[guild_id][mode].append(role)
        await self._update(cursor, guild_id, mode, self.cache[guild_id][mode])

    async def remove_role(
        self, guild_id: int, mode: Mode, role: int, cursor: Cursor = None
    ) -> None:
        "ブロック対象のロールを削除します。"
        self.assert_blocker(guild_id, mode)
        assert len(self.cache[guild_id][mode]) < self.MAX_ROLES, "登録しすぎです。"
        self.cache[guild_id][mode].remove(role)
        await self._update(cursor, guild_id, mode, [])


Role = Union[discord.Role, discord.Object, Literal[0]]


class Blocker(commands.Cog, DataManager):
    def __init__(self, bot: RT):
        self.bot = bot
        super(commands.Cog, self).__init__(self)

    @commands.group(
        "blocker", aliases=["b", "ブロッカー"], extras={
            "headding": {
                "ja": "絵文字,スタンプブロッカー", "en": "Emoji,Stamp blocker"
            }, "parent": "ServerSafety"
        }
    )
    async def blocker(self, ctx: commands.Context):
        """!lang ja
        --------
        特定のロールを持ってる人は絵文字またはスタンプを送信できないようにする機能です。

        Aliases
        -------
        b, ブロッカー

        !lang en
        --------
        This feature prevents people with a specific role from sending emoji or stamps.

        Aliases
        -------
        b"""
        if not ctx.invoked_subcommand:
            await ctx.reply(
                {"ja": "使用方法が違います。",
                 "en": "It is wrong way to use this command."}
            )

    HELP = ("ServerSafety", "blocker")

    @blocker.command("toggle", aliases=["設定", "t"])
    @commands.has_guild_permissions(manage_messages=True)
    @commands.cooldown(1, 10, commands.BucketType.guild)
    async def _toggle(self, ctx: commands.Context, *, mode: DataManager.Mode):
        """!lang ja
        --------
        リアクションか絵文字またはスタンプのブロックの有効/無効の切り替えをします。  
        ですが、有効にしても対象のロールを追加しなければ意味がないので、削除対象のロールの設定を忘れないようにしましょう。

        Parameters
        ----------
        mode : emoji または stamp または reaction
            削除するものです。

        Aliases
        -------
        t, 設定

        !lang en
        --------
        Enable/disable the blocking of emoji or stamps or reaction.  
        But even if you enable it, it will be useless if you don't add the target role, so don't forget to set the target role for deletion.

        Parameters
        ----------
        mode : emoji / stamp / reaction
            It is what RT will delete.

        Aliases
        -------
        t"""
        await ctx.trigger_typing()
        await self.write(ctx.guild.id, mode)
        await ctx.reply("Ok")

    @blocker.group(
        aliases=["ロール", "役職", "r"], 
        extras={
            "headding": {
                "ja": "文字ブロックで削除対象とするロールの設定リストを表示します。",
                "en": "Displays the configuration list of roles to be deleted in the character block."
            }
        }
    )
    async def role(self, ctx: commands.Context):
        """!lang ja
        --------
        削除対象とするロールを管理するコマンドです。  
        `rf!blocker role`と実行すると設定されているものの一覧が表示されます。  
        これで設定しても`rf!blocker toggle`を実行するまでは何も起きません。

        Aliases
        -------
        r, ロール, 役職

        !lang en
        --------
        This command is used to manage the roles to be deleted.  
        If you run `rf!blocker role`, a list of the configured roles will be displayed.    
        If you set it up this way, nothing will happen until you run `rf!blocker toggle`.

        Aliases
        -------
        r"""
        if not ctx.invoked_subcommand:
            if ctx.guild.id in self.cache:
                embed = discord.Embed(
                    title=self.__cog_name__,
                    color=self.bot.Colors.normal
                )
                for mode, roles in list(self.cache[ctx.guild.id].items()):
                    if roles:
                        embed.add_field(
                            name=mode, value="\n".join(
                                f"・<@&{role_id}>" for role_id in roles
                            )
                        )
                await ctx.reply(embed=embed)

    @role.command(aliases=["追加", "a"])
    @commands.cooldown(1, 8, commands.BucketType.guild)
    @commands.has_guild_permissions(manage_messages=True)
    async def add(
        self, ctx: commands.Context, mode: DataManager.Mode, *, role: "Role"
    ):
        """!lang ja
        --------
        所有していると絵文字等を送信することができなくなるロールを設定します。

        Parameters
        ----------
        mode : emoji / stamp / reaction
            絵文字かスタンプかリアクションどっちの時での設定かです。
        role : 役職名,IDまたはメンション
            設定する役職です。

        Aliases
        -------
        a, ついか

        !lang en
        --------
        Set a role that, when owned, will not allow you to send emoji and other text.

        Parameters
        ----------
        mode : emoji / stamp / reaction
            Emoji or Stamp or reaction
        role : role's name, role's ID or role mention
            Target role

        Aliases
        -------
        a"""
        try:
            await self.add_role(ctx.guild.id, mode, role.id)
        except AssertionError:
            await ctx.reply("これ以上設定できないまたはまだ設定が有効になっていません。")
        else:
            await ctx.reply("Ok")

    @role.command(aliases=["削除", "rm"])
    @commands.cooldown(1, 8, commands.BucketType.guild)
    @commands.has_guild_permissions(manage_messages=True)
    async def remove(
        self, ctx: commands.Context, mode: DataManager.Mode, *, role: "Role"
    ):
        """!lang ja
        --------
        所有していると絵文字等を送信することができなくなるロールを削除します。

        Aliases
        -------
        rm, 削除

        !lang en
        --------
        The opposite of `add`.

        Aliases
        -------
        rm"""
        await self.remove_role(ctx.guild.id, mode, role.id)
        await ctx.reply("Ok")

    HEADDING = "[RT.Blocker]"

    def is_should_check(self, author: discord.Member) -> Iterator[str]:
        "ブロックをすべきかを確かめます。"
        for mode, roles in list(self.cache[author.guild.id].items()):
            if any(
                author.get_role(role_id) or role_id == 0
                for role_id in roles
            ):
                yield mode

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if (message.guild and isinstance(message.author, discord.Member)
                and message.guild.id in self.cache):
            # ブロックをするかをチェックする。
            for mode in self.is_should_check(message.author):
                content = ""
                if mode == "emoji" and emoji_count(message.content):
                    # 絵文字のブロックをする。
                    content = "絵文字送信ブロック対象のため"
                elif mode == "stamp" and message.stickers:
                    # スタンプのブロックをする。。
                    content = "スタンプ送信ブロック対象のため"
                if content:
                    # メッセージを削除する。
                    await message.delete()
                    await message.author.send(
                        f"あなたの{message.guild.name}で送った{'以下の' if message.content else ''}メッセージはあなたが{content}削除されました。"
                        + (f"\n>>> {message.content}" if message.content else '')
                    )
                    break

    @commands.Cog.listener()
    async def on_full_reaction_add(self, payload: discord.RawReactionActionEvent):
        if payload.guild_id is not None and payload.guild_id in self.cache:
            for mode in self.is_should_check(payload.member):
                if mode == "reaction":
                    await payload.message.remove_reaction(payload.emoji, payload.member)
                    break


async def setup(bot):
    await bot.add_cog(Blocker(bot))
