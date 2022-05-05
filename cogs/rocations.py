# Free RT - rocations

from __future__ import annotations

from typing import TypeVar, TypedDict, Optional, Any
from collections.abc import Sequence

from collections import OrderedDict
from functools import wraps
from time import time

from discord.ext import commands
import discord

from aiomysql import Pool, Cursor
from ujson import loads, dumps

from util.slash import Context, UnionContext
from util import RT


# データ型等
class Server(TypedDict):
    description: str
    tags: list[str]
    invite: str
    nices: dict[str, Optional[str]]
    raised: float
    name: str
    language: str


RAISE_TIME = 14106  # 3時間55分06秒
Servers = OrderedDict[int, Server]


# 何か必要なもの
CheckFT = TypeVar("CheckFT")


def check(function: CheckFT) -> CheckFT:
    "宣伝が有効になっているか"
    @wraps(function)
    @commands.has_guild_permissions(administrator=True)
    async def new(self: Rocations, ctx: UnionContext, *args, **kwargs):
        await ctx.typing()
        try:
            return await function(self, ctx, *args, **kwargs)
        except Exception as e:
            if ctx.bot.test or isinstance(e, AssertionError):
                raise
            await ctx.reply(
                {"ja": f"エラーが発生しました。\nサーバーを登録をしていますか？\nErrorCode: `{e}`",
                 "en": f"An error has occurred.\nAre you registering a server? \nErrorCode: `{e}`."}
            )
    return new


# ほんへ
class Rocations(commands.Cog):

    TABLE = "Rocations"

    def __init__(self, bot: RT):
        self.bot = bot
        self.pool: Pool = self.bot.mysql.pool

        self.bot.loop.create_task(
            self._prepare_table(), name="Create Rocations table"
        )
        self.bot.rtws.set_event(self.get_rocations)

    async def get_rocations(self, rows: list[Sequence[Any]]):
        "渡されたデータベースの列のデータからRocationsを取得します。バックエンド用"
        data = {}
        for row in rows:
            guild = self.bot.get_guild(row[0])
            nices = loads(row[3])
            reviews = []
            for user_id, nice in filter(lambda x: x[1], nices.items()):
                user = self.bot.get_user(int(user_id)) or \
                    {"name": "名無しの権兵衛", "avatar": ""}
                if not isinstance(user, dict):
                    user = {"avatar": getattr(user.avatar, "url", ""), "name": user.name}
                reviews.append({"user": user, "message": nice})
            data[row[0]] = {
                "name": guild.name, "icon": getattr(guild.icon, "url", ""), "niceCount": len(nices),
                "description": row[1], "tags": loads(row[2]), "reviews": reviews, "invite": row[4],
                "raised": row[5]
            }
        return data

    async def _prepare_table(self):
        # テーブルの準備をする。
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"""CREATE TABLE IF NOT EXISTS {self.TABLE} (
                        GuildID BIGINT PRIMARY KEY NOT NULL, description TEXT, tags JSON,
                        nices JSON, invite TEXT, raised BIGINT, language TEXT
                    );"""
                )

    @commands.group(aliases=("rocal", "サーバー掲示板"), extras={
        "headding": {"ja": "サーバー掲示板", "en": "Server BBS"}, "parent": "RT"
    })
    @commands.cooldown(1, 5, commands.BucketType.guild)
    async def rocations(self, ctx: UnionContext):
        """!lang ja
        --------
        RTのウェブサイトにある[Rocations](https://free-rt.com/rocations)というサーバー掲示板にサーバーを載せたりするためのコマンドです。

        Aliases
        -------
        rocal, サーバー掲示板

        !lang en
        --------
        This command is used to put the server on the server bulletin board called [Rocations](https://free-rt.com/rocations) on the Free RT website.

        Aliases
        -------
        rocal"""
        if not ctx.invoked_subcommand:
            await ctx.reply({"ja": "使用方法が違います。", "en": "It's wrong way to use this command."})

    async def _exists(self, cursor: Cursor, guild_id: int) -> bool:
        # 渡されたサーバーIDのRocationが存在するかどうかをチェックします。
        await cursor.execute(
            f"SELECT GuildID FROM {self.TABLE} WHERE GuildID = %s;",
            (guild_id,)
        )
        return bool(await cursor.fetchone())

    def _assert_description(self, description):
        assert len(description) <= 2000, "文字数が多すぎます。"

    async def _get_invite(self, ctx: UnionContext):
        # 招待リンクを取得します。
        try:
            return (await ctx.guild.vanity_invite()).url
        except discord.Forbidden:
            return (await ctx.channel.create_invite(
                reason="Rocationに登録する招待リンクの作成のため。"
            )).url

    @rocations.command(aliases=("登録", "reg", "add"))
    @commands.cooldown(1, 30, commands.BucketType.guild)
    @commands.has_guild_permissions(administrator=True)
    async def register(self, ctx: UnionContext, *, description):
        """!lang ja
        --------
        Rocationsにサーバーを登録します。

        Parameters
        ----------
        description : str
            サーバーの説明文です。  
            2000文字まで設定が可能で、マークダウンに対応しています。

        Notes
        -----
        マークダウンの書き方については[こちら](https://qiita.com/Qiita/items/c686397e4a0f4f11683d)が参考になると思います。  
        一部対応していない記法がありますがご了承ください。  
        画像を埋め込むことはできます。  
        (HTML埋め込みはできません)

        Aliases
        -------
        add, reg, 登録

        !lang en
        --------
        Registers a server with Rocations.

        Parameters
        ----------
        description : str
            The description of the server.  
            Up to 2000 characters can be set, and markdown is supported.

        Notes
        -----
        For more information on how to write markdown, please refer to [here](https://qiita.com/Qiita/items/c686397e4a0f4f11683d).  
        Please note that there are some notations that are not supported.  
        So you can embed picture to description.  
        (HTML embedding is not supported).

        Aliases
        -------
        add, reg"""
        await ctx.typing()
        self._assert_description(description)
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                if await self._exists(cursor, ctx.guild.id):
                    await ctx.reply({
                        "ja": "既に設定されています。", "en": "Already exists."
                    })
                else:
                    await cursor.execute(
                        f"INSERT INTO {self.TABLE} VALUES (%s, %s, %s, %s, %s, %s, %s);",
                        (ctx.guild.id, description, "[]", r"{}",
                         await self._get_invite(ctx), int(time()),
                         self.bot.cogs["Language"].get(ctx.guild.id))
                    )
                    await ctx.reply(embed=discord.Embed(
                        title="Rocations", description={
                            "ja": f"公開しました。\nhttps://free-rt.com/rocations?search={ctx.guild.id}",
                            "en": f"Published!\nhttps://free-rt.com/rocations?search={ctx.guild.id}"
                        }, color=self.bot.Colors.normal
                    ).set_footer(text={
                        "ja": "Tips: サーバーの表示順位は3時間55分06秒に一度`rf!raise`で上げられるよ。",
                        "en": "Tips: You can use `rf!raise` to raise the server's display order once every 3 hours, 55 minutes, and 06 seconds."
                    }))

    @rocations.command(aliases=("del", "rm", "remove", "削除"))
    @commands.cooldown(1, 30, commands.BucketType.guild)
    @commands.has_guild_permissions(administrator=True)
    async def delete(self, ctx: UnionContext):
        """!lang ja
        --------
        サーバー掲示板からサーバーを削除します。

        Aliases
        -------
        del, rm, remove, 削除

        !lang en
        --------
        Delete server from Rocations.

        Aliases
        -------
        del, rm, remove"""
        await ctx.typing()
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                if await self._exists(cursor, ctx.guild.id):
                    await cursor.execute(
                        f"DELETE FROM {self.TABLE} WHERE GuildID = %s;", (ctx.guild.id,)
                    )
        await ctx.reply("Ok")

    async def _update(self, query: str, args: tuple = ()):
        # 更新を行います。
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(query.replace("<t>", self.TABLE), args)

    @rocations.command(aliases=("t", "タグ"))
    @check
    async def tags(self, ctx: UnionContext, *, tags: str):
        """!lang ja
        --------
        サーバーにタグを設定します。

        Parameters
        ----------
        tags : str
            カンマ(`,`)で分けたタグです。

        Notes
        -----
        タグは1つ25文字以内で7個までタグを登録することができます。

        Examples
        --------
        `rf!rocations tags game,Minecraft,Apex`

        Aliases
        -------
        タグ, t

        !lang en
        --------
        Sets a tag for the server.

        Parameters
        ----------
        tags : str
            The tags are separated by commas (`,`).

        Notes
        -----
        You can register up to 7 tags with a maximum of 25 characters.

        Aliases
        -------
        t

        Examples
        --------
        `rf!rocations tags game,Minecraft,Apex`"""
        assert len(tags := tags.split(",")) <= 7, {"ja": "タグが多すぎます。", "en": "I can't set it up that well."}
        assert all(len(tag) <= 25 for tag in tags), {"ja": "タグは25文字以内にしてください。", "en": "Tags should be no longer than 25 characters."}
        await self._update(
            "UPDATE <t> SET tags = %s WHERE GuildID = %s;", (dumps(tags), ctx.guild.id)
        )
        await ctx.reply("Ok")

    @rocations.command(aliases=("desc", "説明"))
    @check
    async def description(self, ctx: UnionContext, *, description: str):
        """!lang ja
        --------
        サーバーの説明を更新します。

        Parameters
        ----------
        description : str
            サーバーの説明です。  
            マークダウンに対応しています。

        Aliases
        -------
        desc, 説明

        !lang en
        --------
        Setting description of server.

        Parameters
        ----------
        description : str
            Server's description

        Aliases
        -------
        desc"""
        self._assert_description(description)
        await self._update(
            "UPDATE <t> SET description = %s WHERE GuildID = %s;", (
                description, ctx.guild.id
            )
        )
        await ctx.reply("Ok")

    @rocations.command(aliases=("i", "招待"))
    @commands.cooldown(1, 180, commands.BucketType.guild)
    @check
    async def invite(self, ctx: UnionContext):
        """!lang ja
        --------
        掲示板に乗せる招待リンクを更新します。  
        もしバニティリンクが存在する場合はそれが使用されます。

        Aliases
        -------
        i, 招待

        !lang en
        --------
        Update invite link.  
        If vanity link is avaliable, RT use that.

        Aliases
        -------
        i"""
        await self._update(
            "UPDATE <t> SET invite = %s WHERE GuildID = %s;", (
                await self._get_invite(ctx), ctx.guild.id
            )
        )
        await ctx.reply("Ok")

    @rocations.command("raise")
    @commands.cooldown(1, 10, commands.BucketType.user)
    async def raise_(self, ctx: UnionContext):
        """!lang ja
        --------
        サーバー掲示板での表示順位を上げます。  
        3時間55分06秒に一回このコマンドを動かすことができます。  
        また、`/raise`か`rf!raise`でもこのコマンドを実行することができます。

        !lang en
        --------
        Increases the display rank on the server board.  
        You can run this command once every 3 hours 55 minutes 06 seconds.  
        You can also run this command with `/raise` or `rf!raise`."""
        await ctx.typing()
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"SELECT raised FROM {self.TABLE} WHERE GuildID = %s;",
                    (ctx.guild.id,)
                )
                raised = (await cursor.fetchone())[0]
                if (elapsed := (now := time()) - raised) > RAISE_TIME:
                    await cursor.execute(
                        f"UPDATE {self.TABLE} SET raised = %s WHERE GuildID = %s;",
                        (int(now), ctx.guild.id)
                    )
                    await ctx.reply({
                        "ja": "Raised! 表示順位をあげました。",
                        "en": "Raised! I raised the display rank."
                    })
                else:
                    await ctx.reply({
                        "ja": f"まだRaiseできません！\n<t:{(elapsed:=int(time()+(RAISE_TIME-elapsed)))}:R>にRaiseができるようになります。",
                        "en": f"Can't Raise yet!\nYou will be able to Raise when the time is <t:{elapsed}:R>."
                    })

    @commands.command("raise")
    @commands.cooldown(1, 10, commands.BucketType.user)
    async def raise_alias(self, ctx: UnionContext):
        await self.raise_(ctx)

    @discord.slash_command("raise", description="Rocationsでのサーバー表示順位を上げます。")
    async def raise_slash(self, interaction: discord.Interaction):
        ctx = Context(self.bot, interaction, self.raise_alias, "rf!raise")
        await ctx.typing()
        await self.raise_(ctx)


async def setup(bot):
    await bot.add_cog(Rocations(bot))
