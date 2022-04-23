# Free RT - RT Life

from __future__ import annotations

from os.path import exists
from asyncio import all_tasks
from time import time

from discord.ext import commands, tasks

from onami.functools import executor_function
from psutil import virtual_memory, cpu_percent
from aiofiles import open as aioopen
from ujson import load, dumps

from util import RT


class RTLife(commands.Cog):
    def __init__(self, bot: RT):
        self.bot = bot
        if exists("data/rtlife.json"):
            with open("data/rtlife.json", "r") as f:
                self.data = load(f)
        else:
            self.data = {
                "botCpu": [], "botMemory": [], "backendCpu": [], "backendMemory": [],
                "users": [], "guilds": [], "voicePlaying": [], "backendLatency": [], "discordLatency": [],
                "botPoolSize": [], "botTaskCount": [], "backendPoolSize": [], "backendTaskCount": []
            }
        self.bot.rtws.set_event(self.get_status)
        self.update_status.start()

    @executor_function
    def process_psutil(self) -> tuple[float, float]:
        return virtual_memory().percent, cpu_percent(interval=1)

    @executor_function
    def count(
        self, data: tuple, server_status: tuple[float, float],
        latency: float, task_count: int
    ):
        for key in self.data.keys():
            count = None
            if key == "botMemory":
                count = server_status[0]
            elif key == "botCpu":
                count = server_status[1]
            elif key == "users":
                count = len(self.bot.users)
            elif key == "guilds":
                count = len(self.bot.guilds)
            elif key == "voicePlaying":
                count = len(self.bot.voice_clients)
            elif key == "backendLatency":
                count = latency
            elif key == "discordLatency":
                count = round(self.bot.latency * 1000, 1)
            elif key == "botPoolSize":
                count = self.bot.mysql.pool.size
            elif key == "botTaskCount":
                count = task_count
            elif key == "backendPoolSize":
                count = data[0][0]
            elif key == "backendTaskCount":
                count = data[0][1]
            elif key == "backendMemory":
                count = data[1][0]
            elif key == "backendCpu":
                count = data[1][1]
            if count is not None:
                self.data[key].append(count)
                if len(self.data[key]) >= 1008:
                    self.data[key] = self.data[key][-1008:]

    # @tasks.loop(seconds=10)
    @tasks.loop(minutes=10)
    async def update_status(self):
        try: data = await self.bot.rtws.request("get_backend_status", None)
        except: data = ((0, 0), (4, 30))
        # バックエンドとのレイテンシを調べる。
        if self.bot.backend:
            count = time()
            async with self.bot.session.get(
                f"{self.bot.get_url()}/api/ping"
            ) as r:
                if await r.text() == "pong":
                    count = round((time() - count) * 1000, 1)
                elif self.data["backendLatency"]:
                    count = self.data["backendLatency"][-1]
                else:
                    count = 0.0
        else:
            count = self.data["backendLatency"][-1] if self.data["backendLatency"] else 0.0
        await self.count(data, await self.process_psutil(), count, len(all_tasks()))
        async with aioopen("data/rtlife.json", "w") as f:
            await f.write(dumps(self.data))

    def get_status(self, _):
        return self.data

    def cog_unload(self):
        self.update_status.cancel()


def setup(bot):
    bot.add_cog(RTLife(bot))
