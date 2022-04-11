# Free RT - percent

from discord.ext import commands
import discord

class percent(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command(name="%")
    async def percent(self, ctx):
        embed = discord.Embed(title="完了%", description="**39%/100%**", color=0x0066ff)
        embed.set_footer(text="2022年4月11日 午前12時12分")
        await ctx.send(embed=embed)



def setup(bot):
    return bot.add_cog(percent(bot))
