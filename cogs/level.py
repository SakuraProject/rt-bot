# Free RT - Level

from __future__ import annotations

from typing import NewType, TypedDict, Literal, Union, Optional

from dataclasses import dataclass

from discord.ext import commands
import discord

from util.page import EmbedPage
from util import RT, Table


Exp, Level = NewType("Exp", int), NewType("Level", int)
UserMode = Literal["server", "global"]


class LevelData(TypedDict):
    exp: Exp
    level: Level


FIRST_LEVEL = LevelData(exp=0, level=0)


class Reward(TypedDict):
    role_id: int
    replace_role_id: Optional[int]


class LocalLevel(Table):
    __allocation__ = "GuildID"
    onoff: bool
    nof: bool
    data: dict[int, LevelData]
    reward: dict[str, Reward]


class GlobalLevel(Table):
    __allocation__ = "UserID"
    level: LevelData
    nof: bool


@dataclass
class Data:
    l: LocalLevel
    g: GlobalLevel


cooldown = commands.cooldown(1, 5, commands.BucketType.guild)


class Level(commands.Cog):
    def __init__(self, bot: RT):
        self.bot = bot
        self.data = Data(LocalLevel(bot), GlobalLevel(bot))
        self.bot.prefixes = tuple(self.bot.command_prefix)

    def get_now(self, data: LevelData) -> str:
        return f"Level:`{data['level']}`, Exp:`{data['exp']}`"

    @commands.group(
        aliases=("lv", "レベル", "れべる", "れ"), extras={
            "parent": "ServerUseful",
            "headding": {
                "ja": "レベル, レベル報酬ロール",
                "en": "Level, Level reward"
            }
        }
    )
    async def level(self, ctx: commands.Context):
        """!lang ja
        --------
        レベル機能です。RTのいるサーバーで一定数話すとレベルが上がります。
        RTにはグローバルレベルとローカルレベルという2種類のレベリング方式があります。
        グローバルレベルは全サーバー共通で、全世界での自分の位置を知ることができます。
        ローカルレベルはサーバーごとで管理(一定レベルに達したら役職を付与するなど)ができます。

        Aliases
        -------
        lv, レベル, れべる, れ

        !lang en
        --------
        This is a leveling feature, where you level up by talking a certain number of times on a server with RTs.
        There are two types of leveling systems: global level and local level.
        The global level is common and allows you to know your position in the world.
        Local level can be managed on a server-by-server basis (e.g., when you reach a certain level, your position will be raised).

        Aliases
        -------
        lv"""
        if not ctx.invoked_subcommand:
            await ctx.reply(
                embed=discord.Embed(
                    title=self.__cog_name__,
                    color=self.bot.Colors.normal
                ).add_field(
                    name={"ja": f"{ctx.guild.name}でのレベル",
                          "en": f"{ctx.guild.name} Level"},
                    value=self.get_now(
                        self.data.l[ctx.guild.id].get('data', {})
                        .get(str(ctx.author.id), FIRST_LEVEL)
                    )
                ).add_field(
                    name={"ja": "グローバルでのレベル", "en": "Global Level"},
                    value=self.get_now(
                        self.data.g[ctx.author.id].get("level", FIRST_LEVEL)
                    )
                )
            )

    EMOJIS = {
        "g": "<:level_up_global:876339471832997888>",
        "l": "<:level_up_local:876339460252528710>",
        1: "<:No1:795849530448805919> ",
        2: "<:No2:795849531774205994>",
        3: "<:No3:795849531840397323>"
    }

    def make_ranking_embed(
        self, rank: int, fields: list[tuple[str, str]]
    ) -> discord.Embed:
        "ランキング用の埋め込みを作ります。"
        embed = discord.Embed(
            title="ランキング ",
            description=f"{rank/10}ページ目",
            color=self.bot.Colors.normal
        )
        for name, value in fields:
            embed.add_field(name=name, value=value)
        return embed

    @level.command(
        aliases=["rank", "r", "ランキング", "ランク"],
        description="レベルのランキングを表示します。"
    )
    @cooldown
    async def ranking(self, ctx: commands.Context, mode: UserMode):
        """!lang ja
        --------
        レベルランキングを表示します。

        Parameters
        ----------
        mode : `server`か`global`
            serverだとローカルレベル、globalだとグローバルレベルのランキングを表示します。

        Aliases
        -------
        rank, r, ランキング, ランク

        !lang en
        --------
        Displays level ranking.

        Parameters
        ----------
        mode : `server`か`global`
            server: local level
            global: global level

        Aliases
        -------
        rank, r"""
        if (mode == "server" and (
            data := self.data.l[ctx.guild.id].get("data")
        ) is not None) or (data := {
            key: value.get("level", dict(level=0, exp=0))
            for key, value in self.data.g.to_dict().items()
        }):
            fields, embeds = [], []
            for rank, (user_id, data) in enumerate(
                reversed(sorted(data.items(), key=lambda x: x[1]["level"])), 1
            ):
                fields.append(
                    (
                        f"{self.EMOJIS.get(rank, f'{rank}位')}",
                        "{}：`{}`".format(
                            getattr(self.bot.get_user(int(user_id)), 'name', '？？？'),
                            data['level']
                        )
                    )
                )
                if rank % 10 == 0:
                    embeds.append(self.make_ranking_embed(rank, fields))
                    fields = []
                    if mode == "global":
                        # グローバルの場合はメモリが大きくなるので終了する。
                        break
            if fields:
                embeds.append(self.make_ranking_embed(rank, fields))
            if len(embeds) == 1:
                await ctx.reply(embed=embeds[0])
            else:
                await ctx.reply(embed=embeds[0], view=EmbedPage(data=embeds))
        else:
            await ctx.reply("まだありません。")

    @level.group(
        aliases=["rw", "rd", "報酬"],
        description="レベル報酬設定"
    )
    async def reward(self, ctx: commands.Context):
        """!lang ja
        --------
        レベル報酬関連の設定をします。
        `rf!level reward`で現在の設定を表示できます。
        ※設定できるのはローカルレベルのみです。

        Aliases
        -------
        rw, rd, 報酬

        !lang en
        --------
        Configure settings related to level rewards.
        You can use `rf!level reward` to display the current settings.
        Only the local level can be set.

        Aliases
        -------
        rw, rd"""
        if not ctx.invoked_subcommand:
            data: dict[str, Reward] = self.data.l[ctx.guild.id].get("reward")
            if data is None:
                await ctx.reply("まだ設定されていません。")
            else:
                await ctx.reply(
                    embed=discord.Embed(
                        title="レベル報酬",
                        description="\n".join(
                            "`{}`: <@&{}>{}".format(
                                level, reward["role_id"],
                                "" if reward["replace_role_id"] is None else
                                f"\n　　剥奪：<@&{reward['replace_role_id']}>"
                            )
                            for level, reward in list(data.items())
                        ), color=self.bot.Colors.normal
                    )
                )

    manage_role = commands.has_guild_permissions(manage_roles=True)

    @reward.command(
        aliases=("s", "設定"), description="レベル報酬を設定します。"
    )
    @manage_role
    @cooldown
    async def set(
        self, ctx: commands.Context, level: int,
        role: Union[discord.Role, discord.Object], *,
        replace_role: Union[discord.Role, discord.Object] = None
    ):
        """!lang ja
        --------
        レベル報酬を設定します。

        Parameters
        ----------
        level : int
            報酬を渡すために必要なレベル。
        role : ロール
            報酬を与えるレベルに達したときに付与するロールです。
        replace_role : ロール, Optional
            もし報酬を渡すときに代わりに剥奪したいロールがあるときにこの引数を使いましょう。

        Aliases
        -------
        s, 設定

        !lang en
        --------
        Set the level reward.

        Parameters
        ----------
        level : int
            The level required to pass the reward.
        role : role
            The role to grant when the level to give the reward is reached.
        replace_role : role, Optional
            Use this argument if there is a role you want to strip instead of passing the reward.

        Aliases
        -------
        s"""
        if "reward" not in self.data.l[ctx.guild.id]:
            self.data.l[ctx.guild.id].reward = {}
        self.data.l[ctx.guild.id].reward[str(level)] = {
            "role_id": role.id, "replace_role_id": getattr(replace_role, "id", None)
        }
        await ctx.reply("Ok")

    @reward.command(
        aliases=("d", "削除"), description="レベル報酬を削除します。"
    )
    @manage_role
    @cooldown
    async def delete(self, ctx: commands.Context, level: int):
        """!lang ja
        --------
        レベル報酬を削除します。

        Parameters
        ----------
        level : int
            削除する報酬のレベル数。

        Aliases
        -------
        d, 削除

        !lang en
        --------
        Delete level rewards.

        Parameters
        ----------
        level : int
            Level that you wants to delete.

        Aliases
        -------
        d"""
        if "reward" in self.data.l[ctx.guild.id]:
            try:
                del self.data.l[ctx.guild.id].reward[str(level)]
            except KeyError:
                ...
            else:
                return await ctx.reply("Ok")
        await ctx.reply("まだ設定されていません。")

    del manage_role

    @level.group(aliases=("nof", "通知"))
    async def notification(self, ctx: commands.Context):
        """!lang ja
        --------
        リアクションによるレベルアップの通知設定をします。
        デフォルトでOFFです。

        Parameters
        ----------
        mode : global / server
            `global`にした場合は自分の通知設定を設定します。
            `server`にした場合はサーバーでの通知設定をします。
        onoff : bool
            通知をするかどうかです。

        Aliases
        -------
        nof, 通知

        !lang en
        --------
        Sets the notification settings for level-up by reaction.
        Default is off.

        Parameters
        ----------
        mode : global / server
            If set to `global`, set your own notification settings.
            If set to `server`, set the notification settings for the server.
        onoff : bool
            Whether to be notified or not.

        Aliases
        -------
        nof"""
        if ctx.invoked_subcommand is None:
            await ctx.reply("使用方法が違います。")
        else:
            await ctx.reply("Ok")

    @notification.command("global", aliases=("g", "グローバル"))
    async def nof_global(self, ctx: commands.Context, onoff: bool):
        self.data.g[ctx.guild.id].nof = onoff

    @notification.command("server", aliases=("l", "local", "サーバー"))
    @commands.has_guild_permissions(administrator=True)
    async def nof_local(self, ctx: commands.Context, onoff: bool):
        self.data.l[ctx.guild.id].nof = onoff

    def calc(self, exp: int, level: int) -> bool:
        "レベルの計算を行います。"
        return exp >= round((4 * (level ** 3)) / 5)

    def process_level(self, now: LevelData) -> bool:
        "レベルの処理を行う。"
        if "exp" not in now:
            now = FIRST_LEVEL.copy()
        now["exp"] += 1
        if self.calc(**now):
            now["level"] += 1
            return True
        return False

    async def manage_role(
        self, mode: Literal["add", "remove"], message: discord.Message, role_id: int
    ) -> None:
        if role := message.guild.get_role(role_id):
            try:
                await getattr(message.author, f"{mode}_roles")(role)
            except discord.Forbidden:
                await message.reply(
                    {"ja": "レベル報酬である役職を付与または剥奪しようとしましたが、権限がないため付与できませんでした。",
                     "en": "I tried to grant a role that was a level reward, but I couldn't because I didn't have the permission to do so."}
                )
        else:
            await message.rely(
                {"ja": "レベル報酬である役職を付与または剥奪しようとしましたが、その役職が見つからないため付与できませんでした。"
                       f"\nロールID：`{role_id}`",
                 "en": "I tried to grant a role as a level reward, but could not do so because I could not find the role."
                       f"\nRoleID:`{role_id}`"}
            )

    async def on_level(
        self, message: discord.Message, level: Level, mode: Literal["g", "l"]
    ) -> None:
        "レベルアップ時の処理を行う。"
        # 通知を行う。
        if (self.data.l[message.guild.id].get("nof", False)
                or self.data.g[message.author.id].get("nof", False)):
            await message.add_reaction(self.EMOJIS[mode])
        # ローカルならレベル報酬を行う。
        if mode == "l":
            if "reward" in self.data.l[message.guild.id]:
                if (data := self.data.l[message.guild.id].reward.get(str(level))) is not None:
                    await self.manage_role("add", message, data["role_id"])
                    if data["replace_role_id"] is not None:
                        # 剥奪ロールが指定されているならそれを剥奪する。
                        await self.manage_role(
                            "remove", message, data["replace_role_id"]
                        )

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if (message.author.bot or not message.guild
                or message.content.startswith(self.bot.prefixes)):
            return

        if self.data.l[message.guild.id].get("data", True):
            if "data" not in self.data.l[message.guild.id]:
                self.data.l[message.guild.id].data = {}
            if self.process_level(
                now := self.data.l[message.guild.id].data.get(
                    str(message.author.id), FIRST_LEVEL
                ).copy()
            ):
                await self.on_level(message, now["level"], "l")
            self.data.l[message.guild.id].data[str(message.author.id)] = now

        if self.process_level(
            now := self.data.g[message.author.id].get("level", FIRST_LEVEL).copy()
        ):
            await self.on_level(message, now["level"], "g")
        self.data.g[message.author.id].level = now


del cooldown


async def setup(bot):
    await bot.add_cog(Level(bot))
