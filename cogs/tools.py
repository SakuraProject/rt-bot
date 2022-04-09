# Free RT - Tools For Dashboard

from typing import Literal

from asyncio import sleep

from discord.ext import commands
import discord

from rtlib.setting import Context, Setting
from rtlib import RT


class Tools(commands.Cog):
    def __init__(self, bot: RT):
        self.bot = bot

    @commands.command(
        aliases=["stc"], headding={
            "ja": "メッセージを特定のチャンネルに送信します。", "en": "Send message"
        }
    )
    @commands.has_permissions(administrator=True)
    @commands.cooldown(1, 5, commands.BucketType.channel)
    @Setting("guild", "send", channel=discord.TextChannel)
    async def send_(self, ctx: Context, *, content: str):
        await ctx.channel.send(content)
        await ctx.reply(f"{ctx.channel.name}にメッセージを送信しました。")

    @commands.command(
        headding={
            "ja": "IDチェッカー", "en": "ID Checker"
        }
    )
    async def checker(self, ctx):
        await ctx.reply(
            f"ユーザーID: `{ctx.author.id}`\n"
            f"サーバーID: `{ctx.guild.id}`\n"
            f"チャンネルID: `{ctx.channel.id}`"
        )

    @commands.command(
        headding={"ja": "ダッシュボードのローディング表示テスト用のものです。"}
    )
    @commands.cooldown(1, 10, commands.BucketType.guild)
    async def setting_test_loading(self, ctx: Context, number: Literal[1, 2, 3, 4, 5]):
        await sleep(number)
        await ctx.reply("Loading楽しかった？")

    OKES = ["+", "-", "*", "/", ".", "(", ")"]
    OKCHARS = list(map(str, range(10))) + OKES

    def safety(self, word):
        word = word.replace("**", "*")
        return "".join(char for char in str(word) if char in self.OKCHARS)

    @commands.command(
        extras={
            "headding": {
                "ja": "式を入力して計算を行うことができます。", "en": "Calculation by expression"
            }, "parent": "Individual"
        }
    )
    async def calc(self, ctx: Context, *, expression: str):
        """!lang ja
        --------
        渡された式から計算をします。  
        (`+`, `-`, `/`, `*`のみが使用可能です。)

        Parameters
        ----------
        expression : str
            式です。

        !lang en
        --------
        Calculate from the expression given.

        Parameters
        ----------
        expression : str
            Expression"""
        if len(expression) < 25:
            await ctx.reply(f"計算結果：`{await self.bot.loop.run_in_executor(None, eval, self.safety(expression))}`")
        else:
            raise commands.BadArgument("計算範囲が大きすぎます！頭壊れます。")

    @commands.command(
        headding={
            "ja": "文字列を逆順にします。", "en": "Reverse text"
        }
    )
    @Setting("Tools", "文字列逆順")
    async def reverse(self, ctx: Context, *, bigbox):
        await ctx.reply(f"結果：\n```\n{bigbox[::-1]}\n```")

    @commands.command(
        headding={
            "ja": "文字列の交換を行います。", "en": "Replace text"
        }
    )
    @Setting("Tools", "文字列交換")
    async def replace(self, ctx: Context, before, after, *, text):
        await ctx.reply(f"結果：{text.replace(before, after)}")

    @commands.command(
        "RTを追い出します。", headding={
            "ja": "Free RTをサーバーから追い出します。", "en": "Kick RT"
        }
    )
    @commands.has_guild_permissions(administrator=True)
    @Setting("guild")
    async def leave(self, ctx: Context, password="ここに「うらみのワルツ」と入力してください。"):
        if password == "うらみのワルツ":
            await ctx.guild.leave()
            await ctx.reply("* 返事がない。ただの屍のようだ。")
        else:
            await ctx.reply("「うらみのワルツ」を入力しなければ抜けません。")


def setup(bot):
    bot.add_cog(Tools(bot))
