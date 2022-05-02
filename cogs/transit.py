# Free RT - transit

from discord.ext import commands
import aiohttp
from urllib.parse import quote_plus
import discord


class transit(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.BASE_URL = "https://ysmsrv.wjg.jp/transit/index_raw.php?from="

    @commands.command()
    async def transit(self, ctx, depature, to):
        async with aiohttp.ClientSession() as session:
            async with session.get(self.BASE_URL + quote_plus(depature, encoding='utf-8') + "&to=" + quote_plus(to, encoding='utf-8')) as resp:
                sid = await resp.text()
                ssplit = sid.splitlines()
                ssplit.sort(key=len)
                embed = discord.Embed(title=f"{depature}駅から{to}駅までの行き方", description=ssplit[0], color=0x0066ff)
                embed.set_footer(text="乗り換え案内")
                await ctx.send(embed=embed)


async def setup(bot):
    await bot.add_cog(transit(bot))
