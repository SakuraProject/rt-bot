# Free RT Chan - Info

from discord.ext import commands
import discord


class Info(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command(
        "help", slash_command=True, aliases=[
            "h", "へるぷ", "ヘルプ", "invite", "info", "about"
        ], description="ふりーりつたんの操作方法を表示します。"
    )
    async def help(self, ctx):
        await ctx.reply(
            "どうも、ふりーりつたんだよ。\n詳細や招待や使い方はこちら：https://rt-team.github.io/rt-chan"
        )

    @commands.Cog.listener()
    async def on_full_ready(self):
        await self.bot.change_presence(
            activity=discord.Activity(
                name="rf#help | 少女絶賛稼働中！",
                type=discord.ActivityType.watching,
                state="ふりーりつたん"
            )
        )


def setup(bot):
    bot.add_cog(Info(bot))
