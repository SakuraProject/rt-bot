"""Free RT Backend (C) 2022 Free RT
LICENSE : ./LICENSE
README  : ./readme.md
"""

print("Free RT Discord Bot (C) 2022 Free RT\nNow loading...")

from os import listdir
from sys import argv

from logging import handlers
import logging

import discord

from aiohttp import ClientSession
from ujson import load, dumps

from rtlib import RT, mysql, setup, websocket
from data import data, Colors


with open("auth.json", "r") as f:
    secret = load(f)


# Botの準備を行う。
intents = discord.Intents.default()
intents.typing = False
intents.members = True
bot = RT(
    data["prefixes"][argv[-1]], help_command=None, intents=intents,
    allowed_mentions=discord.AllowedMentions(everyone=False, users=False, replied_user=False),
    activity=discord.Game("起動準備"), status=discord.Status.dnd
)
bot.secret = secret
bot.test = argv[-1] != "production"
if not bot.test:
    websocket.WEBSOCKET_URI_BASE = "ws://146.59.153.178"
bot.data = data
bot.admins = data["admins"]
bot.owner_ids = data["admins"]
# 非推奨だがis_adminを作っておく。
bot.is_admin = bot.is_owner
bot.secret = secret
bot.mysql = bot.data["mysql"] = mysql.MySQLManager(
    loop=bot.loop, **secret["mysql"], pool=True,
    minsize=1, maxsize=500 if bot.test else 1000000, autocommit=True
)
bot.pool = bot.mysql.pool
bot.colors = data["colors"]
bot.Colors = Colors
bot._load = False


# 起動中だと教えられるようにするためのコグを読み込む。
bot.load_extension("cogs._first")
# スラッシュマネージャーを設定する。
bot.load_extension("rtlib.slash")
# onamiを読み込む。
bot.load_extension("onami")


@bot.listen()
async def on_ready():
    bot.print("Connected to discord")
    bot.session = ClientSession(loop=bot.loop, json_serialize=dumps)
    bot.unload_extension("cogs._first")

    # 拡張を読み込む。
    setup(bot)
    bot.load_extension("cogs._oldrole")
    for name in listdir("cogs"):
        if not name.startswith(("_", ".")):
            try:
                bot.load_extension(
                    f"cogs.{name[:-3] if name.endswith('.py') else name}"
                )
            except discord.ext.commands.NoEntryPointError as e:
                if "setup" not in str(e):
                    raise e
            else:
                bot.print("[Extension]", "Loaded", name)
    bot.print("Completed to boot Free RT")

    bot.dispatch("full_ready")
    bot._load = True


# loggingの準備をする。
logger = logging.getLogger('discord')
handler = handlers.RotatingFileHandler(
    filename='log/discord.log', encoding='utf-8', mode='w',
    maxBytes=10000000, backupCount=5
)
handler.setLevel(logging.DEBUG)
handler.setFormatter(logging.Formatter(
    "[%(asctime)s][%(levelname)s][%(name)s] %(message)s"
))
logger.addHandler(handler)


bot.run(secret["token"][argv[-1]])

