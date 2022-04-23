# Free RT - Logger

import collections
import logging

from discord.ext import commands, tasks
import discord

from util import RT


class SystemLog(commands.Cog):
    def __init__(self, bot: RT):
        self.bot = bot
        self.names = []
        self.zero_parents = []
        self.authors = []
        self.guilds = []
        self.logging_loop.start()

    def cog_unload(self):
        self.logging_loop.cancel()

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

def setup(bot):
    if not hasattr(bot, "logger"):
        bot.logger = logger = logging.getLogger('discord')
        logger.setLevel(logging.DEBUG)
        handler = logging.handlers.RotatingFileHandler(
            filename='log/discord.log', encoding='utf-8', mode='w',
            maxBytes=10000000, backupCount=50
        )
        handler.setFormatter(logging.Formatter('%(asctime)s:%(levelname)s:%(name)s: %(message)s'))
        logger.addHandler(handler)
    bot.add_cog(SystemLog(bot))
