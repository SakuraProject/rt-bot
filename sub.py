"""ふりーりつたん！ (C) 2022 Free RT
LICENSE : ./LICENSE
README  : ./readme.md
"""

from discord.ext import commands
import discord

from aiohttp import ClientSession
from sys import argv
import ujson
import util

from data import data, RTCHAN_COLORS


desc = """ふりーりつたん - (C) 2022 Free RT
少女起動中..."""
print(desc)

# routeは無効にする。
commands.Cog.route = lambda *args, **kwargs: lambda *args, **kwargs: (args, kwargs)


with open("token.secret", "r", encoding="utf-8_sig") as f:
    secret = ujson.load(f)
TOKEN = secret["token"]["sub"]


prefixes = data["prefixes"]["sub"]


def setup(bot):
    bot.owner_ids = data["admins"]

    @bot.listen()
    async def on_close(loop):
        await bot.session.close()
        del bot.mysql

    bot.mysql = bot.data["mysql"] = util.mysql.MySQLManager(
        loop=bot.loop, user=secret["mysql"]["user"],
        host=(secret["mysql"]["host"] if argv[1] == "production" else "localhost"),
        password=secret["mysql"]["password"], db="mysql",
        pool=True, minsize=1, maxsize=30, autocommit=True)

    util.setup(bot)
    bot.load_extension("jishaku")

    bot._loaded = False

    @bot.event
    async def on_ready():
        if not bot._loaded:
            bot.session = ClientSession(loop=bot.loop)
            for name in ("cogs.tts", "cogs.music", "cogs._sub", "cogs.language"):
                bot.load_extension(name)
            bot.dispatch("full_ready")
            bot._loaded = True
            print("少女絶賛稼働中！")


intents = discord.Intents.default()
intents.members = True
intents.typing = False
intents.guild_typing = False
intents.dm_typing = False
args = (prefixes,)
kwargs = {
    "help_command": None,
    "intents": intents
}
bot = commands.Bot(
    command_prefix=data["prefixes"]["sub"], **kwargs
)
bot.test = argv[1] != "production"


bot.data = data
bot.colors = RTCHAN_COLORS


setup(bot)


bot.run(TOKEN)
