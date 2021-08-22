# RT Ext - Debug

from discord.ext import commands
import discord

from aiofiles import open as async_open, os
from functools import wraps
from io import StringIO


def require_admin(coro):
    @wraps(coro)
    async def new_coro(self, ctx: commands.Context, *args, **kwargs):
        if ctx.author.id in self.bot.admins:
            return await coro(self, ctx, *args, **kwargs)
        else:
            return await ctx.reply(self.ON_NO_ADMIN)
    return new_coro


class Printer:
    def __init__(self, max_characters: int = 2000):
        self.output: str = ""
        self.length: int = 0
        self.stdout = type(
            "PrinterStdout", (), {
                "__init__": lambda *args, **kwargs: None,
                "write": self.write
            }
        )
        self._max = max_characters

    def write(self, text: str):
        self.length += len(text)
        if self.length <= self._max:
            self.output += text

    def print(self, *args, **kwargs) -> None:
        if "file" not in kwargs:
            kwargs["file"] = self.stdout
        return print(*args, **kwargs)


class Debug(commands.Cog):

    ON_NO_ADMIN = "あなたはこのコマンドを実行することができません。"
    OUTPUT_PATH = "_rtlib_debug_output.txt"

    def __init__(self, bot):
        self.bot = bot
        if not hasattr(self.bot, "admins"):
            self.bot.admins = []

    @commands.group()
    async def debug(self, ctx):
        if not ctx.invoked_subcommand:
            await ctx.reply("使用方法が違います。")

    @debug.command(aliases=["exec", "run"])
    @require_admin
    async def execute(self, ctx, *, code):
        printer = Printer()
        exec(
            "async def _program():\n  {}\n{}"
                .format(
                    '\n  '.join(code.splitlines()),
                    "self._program = _program\ndel _program"
                ),
            {"bot": self.bot, "ctx": ctx, "discord": discord,
             "self": self, "print": printer.print}
        )
        result = await self._program()
        async with async_open(self.OUTPUT_PATH, "w") as f:
            await f.write(
                "<<<STDOUT>>>\n{}\n<<<RETURN>>>\n{}"
                    .format(printer.output, str(result))
            )
        await ctx.reply(file=discord.File(self.OUTPUT_PATH))
        await os.remove(self.OUTPUT_PATH)


def setup(bot):
    bot.add_cog(Debug(bot))


if __name__ == "__main__":
    printer = Printer()
    exec(input(), {"print": printer.print})
    print(printer.output)