# Free RT - First

from typing import TYPE_CHECKING

from discord.ext import commands

if TYPE_CHECKING:
    from util import RT


class First(commands.Cog):
    def __init__(self, bot: "RT"):
        self.bot = bot

    @commands.Cog.listener()
    async def on_command_error(self, ctx: commands.Context, error: Exception):
        if isinstance(error, commands.CommandNotFound):
            await ctx.reply("現在起動中のため実行できません。\nすみませんが、もうしばらくお待ちください。")


def setup(bot):
    bot.add_cog(First(bot))
