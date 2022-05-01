# Free RT Util - Bot

from discord.ext import commands

from .dpy_monkey import _setup
from . import mysql_manager as mysql


class RT(commands.AutoShardedBot):
    def __init__(self, *args, **kwargs):
        return super().__init__(*args, **kwargs)

    async def setup_hook(self):
        # 起動中だと教えられるようにするためのコグを読み込む
        await self.load_extension("cogs._first")
        # jishakuを読み込む
        await self.load_extension("jishaku")
        self.mysql = self.data["mysql"] = mysql.MySQLManager(
            loop=self.loop,
            **self.secret["mysql"],
            pool=True,
            minsize=1,
            maxsize=500 if self.test else 1000000,
            autocommit=True
        )  # maxsizeはテスト用では500、本番環境では100万になっている
        self.pool = self.mysql.pool  # bot.mysql.pool のエイリアス

    def print(self, *args, sep: str = "", **kwargs) -> None:
        "[RT log]と色の装飾を加えてprintをします。"
        temp = [*args]
        if len(args) >= 1 and args[0].startswith("[") and args[0].endswith("]"):
            temp[0] = f"\033[93m{args[0]}\033[0m"
        if len(args) >= 2 and args[1].startswith("[") and args[1].endswith("]"):
            temp[1] = f"\033[95m{args[1]}\033[0m"
        return print("\033[32m[RT log]\033[0m", *temp, sep=sep, **kwargs)

    def get_ip(self) -> str:
        return "localhost" if self.test else "60.158.90.139"

    def get_url(self) -> str:
        return f"http://{self.get_ip()}"

    async def close(self) -> None:
        "botが終了するときの動作。on_closeが呼ばれる。"
        self.print("Closing...")
        self.dispatch("close", self.loop)
        await super().close()
        self.print("Bye")

    def get_website_url(self) -> str:
        return "http://localhost/" if self.test else "https://free-rt.com/"

    async def add_cog(self, *args, override: bool = True, **kwargs):
        "add_cogをデフォルトでオーバーライドするようにしたもの。"
        return await super().add_cog(*args, override=override, **kwargs)

    async def setup(self, mode=()) -> None:
        "utilにある拡張cogをすべてもしくは指定されたものだけ読み込みます。"
        return await _setup(self, mode)
