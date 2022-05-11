# Free RT - Monkey_Patch, Author: yaakiyu
# これらのコードはd.pyでのみ動作します。

from __future__ import annotations

from typing import TYPE_CHECKING

from discord.ext import commands
import discord

from .webhooks import webhook_send
from .cacher import CacherPool
from .ext import componesy

if TYPE_CHECKING:
    from .bot import RT


async def _setup(self, mode: tuple[str, ...] = ()) -> None:
    for name in ("on_send", "on_full_reaction", "on_cog_add"):
        if name in mode or mode == ():
            try:
                await self.load_extension("util.ext." + name)
            except commands.ExtensionAlreadyLoaded:
                pass
    for name in ("dochelp", "rtws", "websocket", "debug", "settings", "lib_data_manager"):
        if name in mode or mode == ():
            try:
                await self.load_extension("util." + name)
            except commands.ExtensionAlreadyLoaded:
                pass
    self.cachers = CacherPool()


# webhook_sendとcomponesyを新しく定義する。
discord.abc.Messageable.webhook_send = webhook_send  # type: ignore
discord.ext.commands.Context.webhook_send = webhook_send  # type: ignore
# componesyに関してはモンキーパッチ脱却予定なのでext.easyからのアクセスは非推奨。
discord.ext.easy = componesy  # type: ignore


# on_full_readyが呼ばれた時にtreeをsyncする。
class Monkey(commands.Cog):

    def __init__(self, bot: "RT"):
        self.bot = bot


async def setup(bot):
    await bot.add_cog(Monkey(bot))
