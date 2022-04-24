# Free RT Util - Bot

from typing import Union, Dict, List

from discord.ext import commands

from aiohttp import ClientSession
from aiomysql import Pool

from data import data, Colors

from .mysql_manager import MySQLManager
from .rtws import ExtendedRTWebSocket
from .cacher import CacherPool


class RT(commands.AutoShardedBot):
    mysql: MySQLManager
    pool: Pool
    test: bool
    data: data # type: ignore
    session: ClientSession
    secret: dict
    colors: dict
    Colors: Colors
    rtws: ExtendedRTWebSocket
    cachers: CacherPool

    def print(self, *args, **kwargs) -> None:
        temp =[*args]
        if len(args) >= 1 and args[0].startswith("[") and args[0].endswith("]"):
            temp[0] = f"\033[93m{args[0]}\033[0m"
        if len(args) >= 2 and args[1].startswith("[") and args[1].endswith("]"):
            temp[1] = f"\033[95m{args[0]}\033[0m"
        return print(f"\033[32m[RT log]\033[0m", *temp, **kwargs)

    def get_ip(self) -> str:
        return "localhost" if self.test else "146.59.153.178"

    def get_url(self) -> str:
        return f"http://{self.get_ip()}"

    async def close(self) -> None:
        self.print("Closing...")
        self.dispatch("close", self.loop)
        await super().close()
        self.print("Bye")

    def get_website_url(self) -> str:
        return "http://localhost/" if self.test else "https://free-rt.com/"
