# Free RT - ycmd

from discord.ext import commands
import aiohttp
import urllib.parse
import discord
from ycmd.ycmd import CMD
from ycmd.ClassData import ClassData
class ycmd(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
    @commands.command(
        description="ycmdのコードを実行します",
        extras={"parent":"Admin"}, aliases=["ycmdrun"]
    )
    @commands.is_owner()
    async def ycmd(self, ctx, *, code):
        cmd = CMD()
        cmd.var["ctx"]=ClassData(ctx)
        cmd.var["bot"]=ClassData(self.bot)
        cmd.var["commandclass"]=ClassData(self)
        await cmd.cmdrun(code)



def setup(bot):
    return bot.add_cog(ycmd(bot))
