# Free RT - Log Extension

from discord.ext import commands
import discord
from asyncio import sleep

from datetime import datetime, timedelta
from functools import wraps


CHP_HELP = {
    "ja": (
        "ログ機能。",
        """# ログプラグイン - log
`rf>log`をチャンネルのトピックに入れることでログを表示することができます。  
例：`rf>log` (これをトピックに入れたチャンネルにログが送られます)"""
    ),
    "en": ("...", """...""")
}


def log(mode: str = "normal", force: bool = False):
    # ログ用のデコレータです。
    def decorator(func):
        @wraps(func)
        async def new_function(self, first_arg, *args, **kwargs):
            if mode == "payload":
                guild = self.bot.get_guild(first_arg.guild_id)
            elif mode == "guild":
                guild = first_arg
            elif isinstance(first_arg, discord.Guild):
                guild = first_arg
            else:
                guild = first_arg.guild

            if guild:
                channel = discord.utils.find(
                    lambda ch: (
                        "log-rt" in ch.name
                        or (ch.topic and "rf>log" in ch.topic)
                    ), guild.text_channels
                )

                if channel or force:
                    embed = await func(self, first_arg, *args, **kwargs)
                    if embed and channel:
                        embed.set_footer(
                            text=f"RTログ | {datetime.now().strftime('%Y-%m-%d %H:%M')}"
                        )
                        try:
                            await channel.send(embed=embed)
                        except (discord.errors.Forbidden,
                                discord.errors.HTTPException):
                            pass
        return new_function
    return decorator


class Log(commands.Cog):

    EMOJIS = {
        "bot": "<:bot:876337342116429844>"
    }

    def __init__(self, bot):
        self.bot, self.data = bot, bot.data
        self.team_id = self.bot.owner_ids
        self.c = self.bot.colors["normal"]

    async def cog_load(self):
        await sleep(1.5)
        for lang in CHP_HELP:
            self.bot.cogs["DocHelp"].add_help(
                "ChannelPlugin", "Discord-log",
                lang, *CHP_HELP[lang]
            )

    def parse_time(self, date):
        # 時間を日本時間にして文字列にする。
        return (date + timedelta(hours=9)).strftime('%Y-%m-%d')

    @commands.Cog.listener()
    @log()
    async def on_message(self, message):
        if message.content and ((ever := "@everyone" in message.content) or "@here" in message.content):
            return discord.Embed(
                title="全員メンション",
                description=f"{message.author} ({message.author.id})が{'everyone' if ever else 'here'}メンションをしました。",
                color=self.c
            )

    @commands.Cog.listener()
    @log()
    async def on_member_join(self, member):
        embed = discord.Embed(
            title="メンバーの参加",
            description=self.EMOJIS["bot"] if member.bot else "" + member.mention,
            color=self.c
        )
        embed.add_field(name="ユーザーID", value=str(member.id))
        embed.add_field(
            name="Discord登録日",
            value=self.parse_time(member.created_at)
        )
        embed.set_thumbnail(url=getattr(member.avatar, "url", ""))
        return embed

    @commands.Cog.listener()
    @log()
    async def on_member_remove(self, member):
        embed = discord.Embed(
            title="メンバーの退出",
            description=self.EMOJIS["bot"] if member.bot else "" + member.mention,
            color=self.c
        )
        embed.add_field(name="ユーザーID", value=str(member.id))
        embed.set_thumbnail(url=getattr(member.avatar, "url", ""))
        return embed

    @commands.Cog.listener()
    @log()
    async def on_message_edit(self, before, after):
        embed = discord.Embed(title="メッセージ編集", color=self.c)
        embed.set_author(name=after.author.name, icon_url=getattr(after.author.avatar, "url", ""))
        if before.content != after.content:
            embed.add_field(name="Before", value=before.content)
            embed.add_field(name="After", value=after.content)
            return embed

    @commands.Cog.listener()
    @log("payload")
    async def on_raw_message_delete(self, payload):
        embed = discord.Embed(title="メッセージ削除", color=self.c)
        embed.add_field(name="チャンネル", value=f"<#{payload.channel_id}>")
        value = ("すいません！\n古すぎて取得できませんでした。"
                 if payload.cached_message is None
                 else payload.cached_message.content)
        embed.add_field(name="削除されたメッセージ", value=value)
        return embed

    @commands.Cog.listener()
    @log()
    async def on_guild_channel_delete(self, channel):
        embed = discord.Embed(title="チャンネルの削除", color=self.c)
        embed.add_field(name="チャンネル名", value=channel.name)
        return embed

    @commands.Cog.listener()
    @log()
    async def on_guild_channel_create(self, channel):
        embed = discord.Embed(title="チャンネルの作成", color=self.c)
        embed.add_field(name="チャンネル", value=channel.mention)
        return embed

    @commands.Cog.listener()
    @log()
    async def on_guild_channel_update(self, before, after):
        if before.name != after.name:
            embed = discord.Embed(title="チャンネル名の更新", color=self.c)
            embed.add_field(name="更新前のチャンネル名", value=before.name)
            embed.add_field(name="更新後のチャンネル名", value=after.name)
            return embed

    @commands.Cog.listener()
    @log()
    async def on_guild_update(self, before, after):
        if before.name != after.name:
            embed = discord.Embed(title="チャンネル名の更新", color=self.c)
            embed.add_field(name="更新前のチャンネル名", value=before.name)
            embed.add_field(name="更新後のチャンネル名", value=after.name)
            return embed

    @commands.Cog.listener()
    @log()
    async def on_guild_role_create(self, role):
        embed = discord.Embed(title="役職の作成", color=self.c)
        embed.add_field(name="作成された役職", value=role.mention)
        return embed

    @commands.Cog.listener()
    @log()
    async def on_guild_role_delete(self, role):
        embed = discord.Embed(title="役職の削除", color=self.c)
        embed.add_field(name="削除された役職の名前", value=role.name)
        return embed

    @commands.Cog.listener()
    @log()
    async def on_guild_role_update(self, before, after):
        if before.name != after.name:
            embed = discord.Embed(title="役職の更新", color=self.c)
            embed.add_field(name="更新前の名前", value=before.name)
            embed.add_field(name="更新後の名前", value=after.name)
            return embed

    @commands.Cog.listener()
    @log("guild")
    async def on_member_ban(self, guild, user):
        embed = discord.Embed(title="ユーザーのBAN", color=self.c)
        embed.add_field(name="BANされたユーザー名", value=str(user))
        embed.add_field(name="BANされたユーザーID", value=user.id)
        embed.set_thumbnail(url=user.avatar.url)
        return embed

    @commands.Cog.listener()
    @log("guild")
    async def on_member_unban(self, guild, user):
        embed = discord.Embed(title="ユーザーのBAN解除", color=self.c)
        embed.add_field(name="BAN解除されたユーザー名", value=user)
        embed.add_field(name="BAN解除されたユーザーID", value=user.id)
        embed.set_thumbnail(url=getattr(user.avatar, "url", ""))
        return embed

    @commands.Cog.listener()
    @log()
    async def on_invite_create(self, invite):
        if invite.guild is not None:
            embed = discord.Embed(
                title="招待リンクの作成",
                description=(
                    self.EMOJIS["bot"] if invite.inviter.bot else ""
                    + f"{invite.inviter.mention}による実行"
                ),
                color=self.c
            )
            embed.add_field(name="招待リンク", value=invite.url)
            embed.set_thumbnail(
                url=getattr(invite.inviter.avatar, "url", "")
            )
            return embed

    @commands.Cog.listener()
    @log()
    async def on_invite_delete(self, invite):
        if invite.guild is not None:
            embed = discord.Embed(title="招待リンクの削除", color=self.c)
            embed.add_field(name="招待リンク", value=invite.url)
            return embed


async def setup(bot):
    await bot.add_cog(Log(bot))
