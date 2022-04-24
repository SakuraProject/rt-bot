# Free RT - Logger

from discord.ext import commands, tasks
import discord

from traceback import TracebackException

import collections
import aiofiles
import logging

from util import RT


ERROR_CHANNEL = 962977145716625439


class SystemLog(commands.Cog):
    def __init__(self, bot: RT):
        self.bot = bot
        self.names = []
        self.zero_parents = []
        self.authors = []
        self.guilds = []
        self.errors = set()
        self.logging_loop.start()
        self.error_log_to_discord.start()

    def cog_unload(self):
        self.logging_loop.cancel()
        self.error_log_to_discord.cancel()

    def _make_embed(self):
        name = collections.Counter(self.names).most_common()[0]
        zero_parent = collections.Counter(self.zero_parents).most_common()[0]
        author = collections.Counter(self.authors).most_common()[0]
        guild = collections.Counter(self.guilds).most_common()[0]
        e = discord.Embed(
            title="Free RT command log",
            description=f"1分間で{len(self.names)}回のコマンド実行(以下、実行最多記録)",
            color=self.bot.Colors.unknown
        )
        e.add_field(name="コマンド", value=f"{name[0]}：{name[1]}回")
        e.add_field(name="コマンド(Group)", value=f"{zero_parent[0]}：{zero_parent[1]}回")
        e.add_field(
            name="ユーザー",
            value=f"{self.bot.get_user(author[0])}({author[0]})：{author[1]}回"
        )
        e.add_field(
            name="サーバー",
            value=f"{self.bot.get_guild(guild[0])}({guild[0]})：{guild[1]}回"
        )
        return e

    @tasks.loop(seconds=60)
    async def logging_loop(self):
        if len(self.names) != 0:
            await self.bot.get_channel(961870556548984862) \
                .send(embed=self._make_embed())
            self.names = []
            self.zero_parents = []
            self.authors = []
            self.guilds = []


    @commands.Cog.listener()
    async def on_command(self, ctx):
        self.names.append(ctx.command.name)
        self.zero_parents.append(
            ctx.command.name if len(ctx.command.parents) == 0 \
                else ctx.command.parents[-1].name
        )
        self.authors.append(ctx.author.id)
        self.guilds.append(getattr(ctx.guild, "id", 0))


    @commands.Cog.listener()
    async def on_command_error(self, ctx: commands.Context, error: Exception):
        # エラー時のログ処理。大量のisinstance->returnがあるのはbot_general.pyで処理するから。
        if isinstance(error, (
                commands.CommandNotFound, discord.Forbidden, commands.CommandOnCooldown,
                commands.MemberNotFound, commands.UserNotFound, commands.ChannelNotFound,
                commands.RoleNotFound, commands.BadBoolArgument, commands.MissingRequiredArgument,
                commands.BadArgument, commands.ArgumentParsingError, commands.TooManyArguments,
                commands.BadUnionArgument, commands.BadLiteralArgument, commands.MissingPermissions,
                commands.MissingRole, commands.CheckFailure, AssertionError
            )):
            return
        elif isinstance(error, commands.CommandInvokeError):
            return await self.on_command_error(ctx, error.original)
        elif isinstance(error, AttributeError) and "VoiceChannel" in str(error):
            return
        else:
            error_message = "".join(TracebackException.from_exception(error).format())
            self.errors.add(error_message)
            print("\033[31m" + error_message + "\033[0m")

    @tasks.loop(hours=1)
    async def error_log_to_discord(self):
        # discordの特定のチャンネルにエラーを送信します。
        if len(self.errors) == 0:
            return
        async with aiofiles.open("log/recently_errors.txt") as f:
            await f.write("\n\n".join(self.errors))
        await self.bot.get_channel(ERROR_CHANNEL).send(
            embed=discord.Embed(title="エラーログ", description=f"直近1時間に発生したエラーの回数:{len(self.errors)}"),
            file=discord.File("log/recently_errors.txt")
        )
        self.errors = set()


def setup(bot):
    bot.add_cog(SystemLog(bot))
