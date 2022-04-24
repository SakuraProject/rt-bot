# Free RT - Monkey_Patch, Author: yaakiyu
# これらのコードはd.pyでのみ動作します。

from __future__ import annotations

from discord.ext import commands
from discord import app_commands
import discord

from .bot import RT


def dpy_setup(mode: str = None) -> None:
    "dpy用のセットアップをします。動作はnextcordの場合と同じです。"
    pass

##  ここからスラッシュ関連
# コマンドを標準でハイブリッドにする。
commands.command = commands.hybrid_command
commands.group = commands.hybrid_group


# add_cogの際にデフォルトでオーバーライドするようにする。
original_add_cog = commands.Bot.add_cog

async def _new(self, *args, override: bool = True, **kwargs) -> None:
    return await original_add_cog(*args, override=override, **kwargs)

commands.Bot.add_cog = _new


# on_full_readyが呼ばれた時にtreeをsyncする。
class Monkey(commands.Cog):
    
    def __init__(self, bot: RT):
        self.bot = bot


async def setup(bot):
    await bot.add_cog(Monkey(bot))
