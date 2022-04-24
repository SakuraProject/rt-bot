# Free RT Ext - Debug

from discord.ext import commands
import discord

from jishaku.functools import executor_function
from aiofiles import open as async_open, os
from functools import wraps
import psutil


def require_admin(coro):
    @wraps(coro)
    async def new_coro(self, ctx: commands.Context, *args, **kwargs):
        if ctx.author.id in self.bot.owner_ids:
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
    OUTPUT_PATH = "_util_debug_output.txt"

    def __init__(self, bot):
        self.bot = bot
        if not hasattr(self.bot, "owner_ids"):
            self.bot.owner_ids = []

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

    @debug.command(aliases=["su"])
    @require_admin
    async def insted(self, ctx, member: discord.Member, *, command):
        ctx.message.author = member
        ctx.message.content = f"{ctx.prefix}{command}"
        await self.bot.process_commands(ctx.message)

    async def _reload(self):
        self.bot.cogs["SettingManager"].reset()
        for coro in (
            self.bot.cogs["DocHelp"].on_full_ready(),
            self.bot.cogs["Translator"].on_command_added(),
            self.bot.cogs["ChannelPluginGeneral"].on_command_added()
        ):
            self.bot.loop.create_task(coro)
        self.bot.reload_extension("cogs.server_tool")
        self.bot.reload_extension("cogs.log")
        self.bot.dispatch("help_reload")

    @debug.command(aliases=["rh", "r"])
    @require_admin
    async def reload(self, ctx):
        async with ctx.typing():
            await self._reload()
        await ctx.reply("Ok")

    @executor_function
    def make_monitor_embed(self):
        embed = discord.Embed(
            title="Free-RT-Run info",
            description="Running on Ubuntu Linux",
            color=0x0066ff
        )
        embed.add_field(
            name="Memory",
            value=f"{psutil.virtual_memory().percent}%"
        )
        embed.add_field(
            name="CPU",
            value=f"{psutil.cpu_percent(interval=1)}%"
        )
        embed.add_field(
            name="Disk",
            value=f"{psutil.disk_usage('/').percent}%"
        )
        return embed

    @debug.command()
    @require_admin
    async def monitor(self, ctx):
        await ctx.trigger_typing()
        await ctx.reply(
            embed=await self.make_monitor_embed()
        )


def setup(bot):
    bot.add_cog(Debug(bot))


if __name__ == "__main__":
    printer = Printer()
    exec(input(), {"print": printer.print})
    print(printer.output)
