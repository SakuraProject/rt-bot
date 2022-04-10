# Free RT - percent

from discord.ext import commands
import discord

class percent(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command(name="%")
    async def percent(self, ctx):
        embed = discord.Embed(title="完了%", description="**38%/100%**", color=0x0066ff)
        embed.set_footer(text="2022年4月10日 午後8時57分")
        await ctx.send(embed=embed)



async def setup(bot):
    await bot.add_cog(percent(bot))
