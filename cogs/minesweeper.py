# Free RT - MineSweeper Game Extension

import discord
from discord.ext import commands

from util import minesweeper as Ms


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
        if hasattr(ctx, "interaction"):
            await ctx.reply("マインスイーパーを開始します。")
            ctx.send = ctx.channel.send
        self.games[str(ctx.author.id)] = Ms(x, y, bomb)
        kek, mes, me = 200, ctx.message, False
        l = len(ctx.message.content.split())
        if l != 3 and l != 1:
            return

        while kek == 200:
            game = self.games[str(ctx.author.id)]
            embed = discord.Embed(
                title="マインスイーパー",
                description="".join(("`1 4`のように横何番目と何行目で送信してください。\n爆弾数：",
                                     str(game.bomb), "\n```\n", game.get(" "), "\n```"))
            ).set_footer(text="exitと送信すると終了します。")
            me = await ctx.send(ctx.author.mention, embed=embed)

            mes = await self.bot.wait_for(
                'message',
                check=lambda m: (len(m.content.split()) == 2
                                 or m.content in ["exit", "answer"])
                                 and m.author.id == ctx.author.id
                                 and m.channel == ctx.channel)

            if mes.content == "exit":
                return await me.edit({"ja":"終了","en":"finished"})
            if mes.content == "answer":
                await me.edit("```\n" + game.get_answer(" ") + "\n```")
                continue

            x, y = mes.content.split()
            try:
                kek = game.set(int(x), int(y))
            except ValueError:
                pass
            if kek in (410, 301): break
            try:
                await mes.delete()
            except BaseException:
                pass
            try:
                await me.delete()
            except BaseException:
                pass

        if kek == 410:
            embed = discord.Embed(
                title="あなたの負けです。",
                description="\n```\n" + game.get_answer(" ") + "\n```"
            )
            return await me.edit(embed=embed)
        elif kek == 301:
            embed = discord.Embed(
                title="あなたの勝ちです。",
                description="\n```\n" + game.get_answer(" ") + "\n```"
            )
            return await me.edit(embed=embed)

    @commands.command()
    async def msd(self, ctx, a: discord.Member):
        if not a:
            return await ctx.reply("```\n" + str(len(self.games)) + "\n```")
        else:
            return ctx.reply("```\n" + self.games[str(a.id)].get() + "\n```")


def setup(bot):
    return bot.add_cog(Mines(bot))
