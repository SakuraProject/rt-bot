# Free RT - Token Remover

from typing import DefaultDict, List

from discord.ext import commands, tasks
import discord

from collections import defaultdict
from re import findall
from time import time

from util import RT


class TokenRemover(commands.Cog):

    DEFAULT_TIMEOUT = 900

    def __init__(self, bot: RT):
        self.bot = bot
        self.cache: DefaultDict[int, DefaultDict[int, List[int, float]]] = \
            defaultdict(lambda: defaultdict(lambda: [0, time() + self.DEFAULT_TIMEOUT]))
        self.cache_remover.start()

    def check_token(self, content: str) -> bool:
        "TOKENが含まれているか確認します。"
        return bool(findall(
            r"[N]([a-zA-Z0-9]{23})\.([a-zA-Z0-9]{6})\.([a-zA-Z0-9]{27})", content
        ))

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if not message.guild or message.author.id == self.bot.user.id:
            return

        if self.check_token(message.content):
            self.cache[message.guild.id][message.author.id][0] += 1
            self.cache[message.guild.id][message.author.id][1] = \
                time() + self.DEFAULT_TIMEOUT
            if self.cache[message.guild.id][message.author.id][0] == 5:
                await message.reply("TOKENなるものを送るのをやめてください。")
            elif self.cache[message.guild.id][message.author.id][0] == 8:
                try:
                    await message.author.ban(reason="TOKENと思われるものを送っていたため。")
                except Exception:
                    pass
                finally:
                    del self.cache[message.guild.id][message.author.id]

    @tasks.loop(seconds=30)
    async def cache_remover(self):
        now = time()
        for guild_id in list(self.cache.keys()):
            for user_id in list(self.cache[guild_id].keys()):
                if self.cache[guild_id][user_id][1] < now:
                    del self.cache[guild_id][user_id]
            if not self.cache[guild_id]:
                del self.cache[guild_id]

    def cog_unload(self):
        self.cache_remover.cancel()


def setup(bot):
    bot.add_cog(TokenRemover(bot))
