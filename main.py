"""Free RT Backend (C) 2022 Free RT
LICENSE : ./LICENSE
README  : ./readme.md
"""

from os import listdir
from sys import argv

import discord

from aiohttp import ClientSession
from ujson import load, dumps

from util import RT, websocket
from data import data, Colors


print("Free RT Discord Bot (C) 2022 Free RT\nNow loading...")

with open("auth.json", "r") as f:
    secret = load(f)

# Botの準備を行う。
intents = discord.Intents.default()  # intents指定
intents.typing = False
intents.members = True
bot = RT(
    data["prefixes"][argv[-1]],
    help_command=None,
    intents=intents,
    allowed_mentions=discord.AllowedMentions(
        everyone=False,
        users=False,
        replied_user=False
    ),
    activity=discord.Game("起動準備"),
    status=discord.Status.dnd)  # RTオブジェクトはcommands.Botを継承している
bot.test = argv[-1] != "production"  # argvの最後がproductionかどうか
if not bot.test:
    websocket.WEBSOCKET_URI_BASE = "ws://60.158.90.139"
bot.data = data  # 全データアクセス用、非推奨
bot.owner_ids = data["admins"]
bot.secret = secret  # auth.jsonの内容を入れている

bot.colors = data["colors"]  # 下のColorsを辞書に変換したもの
bot.Colors = Colors  # botで使う基本色が入っているclass


@bot.listen()
async def on_ready():
    bot.print("Connected to discord")
    # 起動中いつでも使えるaiohttp.ClientSessionを作成
    bot.session = ClientSession(loop=bot.loop, json_serialize=dumps)
    await bot.unload_extension("cogs._first")

    # 拡張を読み込む
    await bot.setup()
    await bot.load_extension("cogs._oldrole")  # oldroleだけ特別に読み込んでいる
    for name in listdir("cogs"):
        if not name.startswith(("_", ".")):
            try:
                await bot.load_extension(
                    f"cogs.{name[:-3] if name.endswith('.py') else name}")
            except Exception as e:
                print(e)
            else:
                bot.print("[Extension]", "Loaded", name)  # ロードログの出力
    bot.print("Completed to boot Free RT")

    bot.dispatch("full_ready")  # full_readyイベントを発火する


# 実行
bot.run(secret["token"][argv[-1]])
