# Free RT - MineSweeper Game Extension

from discord.ext import commands


class Mines(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.games = {}

    @commands.command(
        aliases=["ms", "MS"],
        extras={
            "headding": {"ja": "マインスイーパー",
                         "en": "Minesweeper"},
            "parent": "Entertainment"
        }
    )
    async def minesweeper(self, ctx, x: int = 9, y: int = 9, bomb: int = 12):
        """!lang ja
        --------
        マインスイーパーというゲームで遊びます。

        Aliases
        -------
        ms, MS

        !lang en
        --------
        Play Minesweeper.

        Aliases
        -------
        ms, MS
        """
        return await ctx.send(
            "申し訳ありませんが、freeRTでの書き直しにより"
            "このコマンドは現在使用できません。もうしばらくお待ちください...")


async def setup(bot):
    await bot.add_cog(Mines(bot))
