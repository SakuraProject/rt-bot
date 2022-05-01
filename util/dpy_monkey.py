# Free RT - Monkey_Patch, Author: yaakiyu
# これらのコードはd.pyでのみ動作します。

from __future__ import annotations

from typing import TYPE_CHECKING

from discord.ext import commands

from .cacher import CacherPool

if TYPE_CHECKING:
    from .bot import RT


async def _setup(self, mode: Tuple[str, ...] = ()) -> None:
    for name in ("on_send", "on_full_reaction", "on_cog_add"):
        if name in mode or mode == []:
            try:
                await self.load_extension("util.ext." + name)
            except commands.ExtensionAlreadyLoaded:
                pass
    for name in ("dochelp", "rtws", "websocket", "debug", "settings", "lib_data_manager"):
        if name in mode or mode == []:
            try:
                await self.load_extension("util." + name)
            except commands.ExtensionAlreadyLoaded:
                pass
    self.cachers = CacherPool()


# on_full_readyが呼ばれた時にtreeをsyncする。
class Monkey(commands.Cog):

    def __init__(self, bot: "RT"):
        self.bot = bot


async def setup(bot):
    await bot.add_cog(Monkey(bot))
