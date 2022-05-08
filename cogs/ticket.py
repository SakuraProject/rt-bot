# Free RT - Ticket

from typing import TYPE_CHECKING, Union, Optional, Dict, List

from time import time

from discord.ext import commands, tasks
import discord

from ujson import loads, dumps

from util import RolesConverter
from util import componesy

if TYPE_CHECKING:
    from aiomysql import Pool

    class NewInteraction(discord.Interaction):
        member: Union[discord.Member, discord.User]


class RealNewInteraction:
    def __init__(self, interaction: discord.Interaction):
        self.interaction = interaction
        self.member = interaction.user

    def __getattr__(self, name):
        return getattr(self.interaction, name)


# 定数を設定する。
TITLE = "[Ticket]"
CUSTOM_ID = "rt_ticket"
COOLDOWN = 150
TABLES = ("TicketMessage", "TicketRoles")
VIEW = componesy.View("TicketView")
VIEW.add_item(
    discord.ui.Button, None, label="Ticket",
    emoji="🎫", custom_id=CUSTOM_ID
)
VIEW = VIEW()


class DataManager:
    def __init__(self, pool: "Pool"):
        self.pool = pool

    async def prepare_table(self) -> None:
        """テーブルを作成します。"""
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"""CREATE TABLE IF NOT EXISTS {TABLES[0]} (
                        GuildID BIGINT PRIMARY KEY NOT NULL,
                        ChannelID BIGINT, Content TEXT
                    );"""
                )
                await cursor.execute(
                    f"""CREATE TABLE IF NOT EXISTS {TABLES[1]} (
                        ChannelID BIGINT PRIMARY KEY NOT NULL,
                        Roles JSON
                    )"""
                )

    async def set_message(self, channel: discord.TextChannel, content: str) -> None:
        """チケット作成時に送信するメッセージを設定します。"""
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"""INSERT INTO {TABLES[0]}
                    VALUES (%s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        ChannelID = %s, Content = %s;""",
                    (channel.guild.id, channel.id,
                     content, channel.id, content)
                )

    async def delete_message(self, guild_id: int) -> None:
        """指定されたサーバーに設定されているメッセージを削除します。"""
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"SELECT GuildID FROM {TABLES[0]} WHERE GuildID = %s;",
                    (guild_id,)
                )
                assert await cursor.fetchone(), "見つかりませんでした。"
                await cursor.execute(
                    f"DELETE FROM {TABLES[0]} WHERE GuildID = %s;",
                    (guild_id,)
                )

    async def read(self, guild_id: int) -> Optional[str]:
        """指定されたサーバーに設定されているメッセージを読み込みます。"""
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"SELECT Content FROM {TABLES[0]} WHERE GuildID = %s;",
                    (guild_id,)
                )
                if (row := await cursor.fetchone()):
                    return row[0]

    async def write_roles(self, channel_id: int, roles: List[int]) -> None:
        "役職設定を保存します。"
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"""INSERT INTO {TABLES[1]} VALUES (%s, %s)
                        ON DUPLICATE KEY UPDATE Roles = %s;""",
                    (channel_id, dumped := dumps(roles), dumped)
                )

    async def read_roles(self, channel_id: int) -> List[int]:
        "役職設定を読み込みます。"
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"SELECT Roles FROM {TABLES[1]} WHERE ChannelID = %s;",
                    (channel_id,)
                )
                if (row := await cursor.fetchone()):
                    return loads(row[0])
                return []


class Ticket(commands.Cog, DataManager):
    def __init__(self, bot):
        self.bot = bot
        self.cooldown: Dict[int, float] = {}
        self.cooldown_killer.start()

    async def cog_load(self):
        # データベースの準備をする。
        super(commands.Cog, self).__init__(self.bot.mysql.pool)
        await self.prepare_table()

    def cog_unload(self):
        self.cooldown_killer.cancel()

    @tasks.loop(minutes=5)
    async def cooldown_killer(self):
        # 放置されたクールダウンのキャッシュは削除する。
        now = time()
        for mid in list(self.cooldown.keys()):
            if self.cooldown[mid] <= now:
                del self.cooldown[mid]

    @commands.command(
        extras={
            "headding": {
                "ja": "チケットチャンネル作成用のパネルを作成します。",
                "en": "Ticket panel"
            }, "parent": "ServerPanel"
        }
    )
    @commands.has_permissions(manage_channels=True)
    async def ticket(self, ctx, title, description, *, roles: RolesConverter = []):
        """!lang ja
        --------
        チケットチャンネル作成用のパネルを作成します。

        Parameters
        ----------
        title : str, default 
            チケットパネルのタイトルです。
        description : str
            チケットパネルの説明欄に入れる文章です。  
            改行や空白を含めたい場合は`"`で文章を囲んでください。
        roles : 役職名または役職のメンション, optional
            作成されるチケットチャンネルを見ることのできる役職です。  
            指定しない場合は管理者権限を持っている人とチケットチャンネルを作った人のみが見れます。  
            `, `(半角のカンマと空白)で分けることで複数指定も可能です。

        Notes
        -----
        このコマンドはチャンネル管理権限がある人でしか実行できません。  
        もしこのパネルを無効化したい場合は単純に作成したパネルのメッセージを削除すれば良いです。  
        チケットチャンネル作成時に何かメッセージを送信してほしい場合は、チケットのあるチャンネルで以下のコマンドを実行して設定できます。
        ```
        rf!tfm メッセージ内容 (もしオフにしたい場合は`off`)
        ```
        ※一つのサーバーにつき一つまで設定が可能です。  
        また、チケットチャンネルを見れる人は`rf!close`でそのチャンネルを削除することができます。  
        削除ではなくアーカイブするようにすることもできます。  
        アーカイブしたい場合はアーカイブ用のカテゴリーを作りそのカテゴリーの名前の最後に`RTAC`をつけてください。

        Examples
        --------
        `rf!ticket 問い合わせ モデレーター`

        !lang en
        --------
        Creates a panel for creating a ticket channel.

        Parameters
        ----------
        title : str, default 
            The title of the ticket panel.
        description : str
            The text to put in the description field of the ticket panel.  
            If you want to include line breaks or spaces, enclose the text with `"`.
        roles : name of the role or a mention of the role, optional
            The role that can see the ticket channel being created.  
            If not specified, only the administrator and the creator of the ticket channel will be able to see it.  
            It is possible to specify more than one, and they can be separated by `, ` (half-width commas and spaces).

        Notes
        -----
        This command can only be executed by someone with channel management privileges.  
        If you want to disable this panel, you can simply delete the panel you created.  
        If you want some message to be sent when a ticket channel is created, you can set it in the channel with the ticket by using the following command.
        ```
        rf!tfm Message content (or `off` if you want to turn it off)
        ```
        You can also use `rf!close` to delete a ticket channel.  
        It can also be archived instead of deleted.  
        In that case, create a category for archiving and add `RTAC` to the end of the category name.

        Examples
        --------
        `rf!ticket query moderator`"""
        if ctx.guild and ctx.channel.category and str(ctx.channel.type) == "text":
            if roles:
                await self.write_roles(ctx.channel.id, [role.id for role in roles])
            embed = discord.Embed(
                title=title,
                description=description,
                color=self.bot.colors["normal"]
            )
            await ctx.webhook_send(
                username=ctx.author.name, avatar_url=getattr(ctx.author.avatar, "url", ""),
                content="RTチケットパネル, 2", embed=embed, wait=True,
                replace_language=False, view=VIEW
            )
        else:
            await ctx.reply(
                {"ja": "このコマンドはカテゴリーにあるテキストチャンネルのみ動作します。",
                 "en": "This command can run on only text channel."}
            )

    @commands.command()
    @commands.has_permissions(manage_channels=True)
    async def tfm(self, ctx: commands.Context, *, content: Union[bool, str]):
        # チケットメッセージ設定用コマンドです。
        await ctx.typing()
        if isinstance(content, bool) and not content:
            try:
                await self.delete_message(ctx.guild.id)
            except AssertionError:
                return await ctx.reply(
                    {"ja": "まだチケットメッセージは設定されていません。",
                     "en": "Ticket message is not set yet."}
                )
        else:
            await self.set_message(ctx.channel, content)
        await ctx.reply("Ok")

    @commands.command(description="チケットチャンネルを閉じます。")
    @commands.cooldown(1, 30, commands.BucketType.user)
    async def close(self, ctx: commands.Context):
        if ctx.channel.topic and "RTチケットチャンネル" in ctx.channel.topic:
            if category := discord.utils.find(
                lambda c: c.name.endswith("RTAC"), ctx.guild.categories
            ):
                await ctx.channel.edit(
                    category=category, topic=None, overwrites=category.overwrites
                )
            else:
                await ctx.channel.delete()
        else:
            await ctx.reply("ここはチケットチャンネルではないので削除できません。")

    def make_channel_name(self, name: str) -> str:
        # チケットチャンネル用の名前を作る関数です。
        return (name[:90] if len(name) > 90 else name) + "-rtチケット"

    @commands.Cog.listener()
    async def on_interaction(self, interaction: discord.Interaction):
        if interaction.data.get("custom_id", "") == CUSTOM_ID:
            # ボタンによるチケットチャンネル作成もする。
            try:
                await interaction.response.defer()
            finally:
                await self.on_ticket(RealNewInteraction(interaction))

    async def on_ticket(self, payload: Union["NewInteraction", discord.RawReactionActionEvent]):
        if ((hasattr(payload, "emoji") and str(payload.emoji) != "🎫") or payload.member.bot
                or not payload.message.embeds or not payload.message.guild
                or not payload.message.content.startswith("RTチケットパネル, ")):
            return

        # リアクションを追加/削除した人の名前でチケットチャンネル名を作る。
        channel_name = self.make_channel_name(payload.member.display_name)
        # リアクションを押した人が既にチャンネルを作成している場合はそのチャンネルを取得する。
        channel = discord.utils.find(
            lambda c: c.name == channel_name and c.category and not c.category.name.endswith("RTAC"),
            payload.message.guild.text_channels,
        )

        if channel:
            # もし既にチケットチャンネルが存在するならそのチャンネルの削除を行う。
            await channel.delete(reason=f"{TITLE}チケット削除のため。")
        else:
            # もしリアクションが押されたなら。
            # クールダウンが必要ならチャンネルを作成しない。
            if (error := (now := time()) - self.cooldown.get(payload.member.id, 0.0)) < COOLDOWN:
                await payload.member.send(
                    {"ja": f"{payload.member.mention}, チケットチャンネルの作成にクールダウンが必要なため{error}秒待ってください。",
                     "en": f"{payload.member.mention}, It want cooldown, please wait for {error} seconds."},
                    delete_after=5, target=payload.member.id
                )
            else:
                self.cooldown[payload.member.id] = now

                # チケットチャンネルの作成に必要な情報を集める。
                roles = map(
                    payload.message.guild.get_role,
                    await self.read_roles(payload.channel_id)
                ) if payload.message.content.endswith(", 2") else [
                    payload.message.guild.get_role(
                        int(payload.message.content[11:])
                    ) if len(payload.message.content) > 15 else None
                ]
                # overwritesを作る。
                perms = {
                    payload.message.guild.default_role: discord.PermissionOverwrite(read_messages=False),
                    payload.member: discord.PermissionOverwrite(read_messages=True)
                }
                if roles:
                    # もしroleが指定されているならroleもoverwritesに追加する。
                    for role in roles:
                        perms[role] = discord.PermissionOverwrite(
                            read_messages=True
                        )
                # チケットチャンネルを作成する。
                channel = await payload.message.channel.category.create_text_channel(
                    channel_name, overwrites=perms, topic=f"RTチケットチャンネル：{payload.member.id}"
                )
                await channel.send(
                    {"ja": f"{payload.member.mention}, ここがあなたのチャンネルです。\n`rf!close`で閉じれます。",
                     "en": f"{payload.member.mention}, Here is your channel!\nYou can close this channel by `rf!close`."},
                    target=payload.member.id
                )
                if (first := await self.read(payload.guild_id)):
                    await channel.send(first)

    @commands.Cog.listener()
    async def on_full_reaction_add(self, payload):
        await self.on_ticket(payload)

    @commands.Cog.listener()
    async def on_full_reaction_remove(self, payload):
        await self.on_ticket(payload)


async def setup(bot):
    await bot.add_cog(Ticket(bot))
