# Free RT - Tools For Dashboard

from asyncio import wait_for, TimeoutError

from discord.ext import commands

from util.settings import Context
from util import RT


class Tools(commands.Cog):
    def __init__(self, bot: RT):
        self.bot = bot

    @commands.command(
        aliases=["stc"],
        extras={
            "headding": {
                "ja": "メッセージを特定のチャンネルに送信します。", "en": "Send message"
            }
        }
    )
    @commands.has_permissions(administrator=True)
    @commands.cooldown(1, 5, commands.BucketType.channel)
    async def send_(self, ctx: Context, *, content: str):
        await ctx.send(content)
        await ctx.reply(f"{ctx.channel.name}にメッセージを送信しました。")

    @commands.command(
        extras={
            "headding": {
                "ja": "IDチェッカー", "en": "ID Checker"
            }
        }
    )
    async def checker(self, ctx):
        await ctx.reply(
            f"ユーザーID: `{ctx.author.id}`\n"
            f"サーバーID: `{ctx.guild.id}`\n"
            f"チャンネルID: `{ctx.channel.id}`"
        )

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
        try:
            x = await wait_for(
                self.bot.loop.run_in_executor(None, eval, self.safety(expression)),
                5, loop=self.bot.loop)
        except SyntaxError:
            raise commands.BadArgument("計算式がおかしいです！")
        except ZeroDivisionError:
            raise commands.BadArgument("0で割り算することはできません!")
        except TimeoutError:
            raise commands.BadArgument("計算範囲が大きすぎます！頭壊れます。")
        await ctx.reply(f"計算結果：`{x}`")

    @commands.command(
        extras={
            "headding": {
                "ja": "文字列を逆順にします。", "en": "Reverse text"
            }
        }
    )
    async def reverse(self, ctx: Context, *, bigbox):
        await ctx.reply(f"結果：\n```\n{bigbox[::-1]}\n```")

    @commands.command(
        extras={
            "headding": {
                "ja": "文字列の交換を行います。", "en": "Replace text"
            }
        }
    )
    async def replace(self, ctx: Context, before, after, *, text):
        await ctx.reply(f"結果：{text.replace(before, after)}")

    @commands.command(
        "RTを追い出します。", extras={
            "headding": {
                "ja": "Free RTをサーバーから追い出します。", "en": "Kick RT"
            }
        }
    )
    @commands.has_guild_permissions(administrator=True)
    async def leave(self, ctx: Context, password="ここに「うらみのワルツ」と入力してください。"):
        if password == "うらみのワルツ":
            await ctx.guild.leave()
            await ctx.reply("* 返事がない。ただの屍のようだ。")
        else:
            await ctx.reply("「うらみのワルツ」を入力しなければ抜けません。")


def setup(bot):
    bot.add_cog(Tools(bot))
