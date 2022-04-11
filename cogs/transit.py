# Free RT - transit

from discord.ext import commands
import aiohttp
import urllib.parse
import discord

class transit(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command(name="transit")
    async def transit(self, ctx, depature, to):
        async with aiohttp.ClientSession() as session:
            async with session.get("https://ysmsrv.wjg.jp/transit/index_raw.php?from="+urllib.parse.quote_plus(depature, encoding='utf-8')+"&to="+urllib.parse.quote_plus(to, encoding='utf-8')) as resp:
                sid = await resp.text()
                ssplit = sid.splitlines()
                ssplit.sort(key=len)
                embed = discord.Embed(title=depature+"駅から"+to+"駅までの行き方", description=ssplit[0], color=0x0066ff)
                embed.set_footer(text="乗り換え案内")
                await ctx.send(embed=embed)



def setup(bot):
    return bot.add_cog(transit(bot))
