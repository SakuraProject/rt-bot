"""Cogの追加/削除時に呼び出される`on_cog_add/remove`というイベントを作るためのエクステンションです。  
`bot.load_extension("util.ext.on_cog_add")`で有効化することができます。  
また`util.setup(bot)`でも有効化することができます。

# Examples
```python
@bot.event
async def on_cog_add(cog):
    print("Added cog", cog.__name__)

@bot.event
async def on_cog_remove(cog):
    print("Removed cog", cog.__name__)
```"""

from discord.ext import commands
from copy import copy


class OnCogAdd(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self._default_add_cog = copy(self.bot.add_cog)
        self._default_remove_cog = copy(self.bot.remove_cog)
        self.bot.add_cog = self._add_cog
        self.bot.remove_cog = self._remove_cog

    def _add_cog(self, cog, **kwargs):
        self.bot.dispatch("cog_add", cog)
        return self._default_add_cog(cog, **kwargs)

    def _remove_cog(self, name):
        cog = self.bot.cogs[name]
        self.bot.dispatch("cog_remove", cog)
        return self._default_remove_cog(name)


async def setup(bot):
    await bot.add_cog(OnCogAdd(bot))
