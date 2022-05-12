"""
freeRT式新データベースマネージャーです。
このマネージャーはdiscord.pyのCogのように使うことができます。
※他のbotには応用しにくい仕組みとなっています。申し訳ありません。
コード例:
```python
from util import db

class Managerrr(db.DBManager):
    def __init__(self, bot):
        self.bot = bot

    async def manager_load(self, cursor):
        # マネージャーが読み込まれた時の特殊関数。
        await cursor.execute("CREATE TABLE user(ID BIGINT, description TEXT, fuga TEXT)")

    async def check_user_id(self, obj: Any):
        return util.isintable(obj) and self.bot.get_user(obj)

    @db.command()
    async def add_user(self, cursor, user: str):
        if not self.check_user_id(user):
            return False
        await cursor.execute("INSERT INTO USERS VALUES(%s, %s, %s)", (int(user), "", ""))

    @db.command(auto=False)
    async def get_user(self, conn, user_id: str):
        if not self.check_user:
            return False
        async with conn.cursor() as cursor:
            await cursor.execute("SELECT * FROM USERS WHERE ID=%s", (user_id,))
            return await cursor.fetchone()

class Coooog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    async def cog_load(self):
        self.db = await self.bot.add_db_manager(Managerrr(bot))

    @commands.command()
    async def datacheck(self, ctx, id: str):
        result = self.db.get_user.run(id)
        await ctx.send(result if result else "見つかりませんでした。")
```
"""

from discord.ext import commands

import aiomysql

from inspect import iscoroutinefunction


async def mysql_connect(*args, **kwargs):
    "全て移行が終了した後に使う予定のmysql接続用関数。"
    return await aiomysql.create_pool(*args, **kwargs)


class DBManager:
    "データベースマネージャーです。db.command()デコレータが着いたものをコマンドとして扱います。"

    def __init_subclass__(cls):
        cls.commands = []
        for m in dir(cls):
            obj = getattr(cls, m)
            if isinstance(obj, Command):
                obj._manager = cls
                setattr(cls, m, obj)
                cls.commands.append(obj)

        return cls

    async def manager_load(self, _):
        pass


class Command:

    def __init__(self, coro, **kwargs):
        self._manager = None
        self.__bot: commands.Bot = None
        self._callback = coro
        self.__kwargs = kwargs

    async def __call__(self, *args, **kwargs):
        # 単純に呼び出すだけ。自動cursor付与などは一切しない。
        return await self._callback(self._manager, *args, **kwargs)

    async def run(self, *args, **kwargs):
        if not self._manager or not self.__bot:
            raise RuntimeError("Managerもしくはbotが見つかりません。")

        async with self.__bot.pool.acquire() as conn:
            if kwargs.get("auto"):
                async with conn.cursor() as cursor:
                    result = await self._callback(self._manager, cursor, *args, **kwargs)
            else:
                result = await self._callback(self._manager, conn, *args, **kwargs)

        # releaseして、使っていないconnectionをしまう。
        self.__bot.pool.release()
        return result


def command(**kwargs):
    "これがついた関数をコマンドとして扱うデコレータです。外部から`.run(...)`で呼び出せます。"
    def deco(func):
        if not iscoroutinefunction(func):
            raise ValueError("コマンドはコルーチンである必要があります。")
        return Command(func)
    return deco


async def add_db_manager(bot: commands.Bot, manager: DBManager):
    "botにDBManagerを追加します。"
    for m in manager.commands:
        m.__bot = bot
        m._manager = manager
    if not isinstance(manager, DBManager):
        raise ValueError("引数managerはDBManagerのサブクラスである必要があります。")

    if not hasattr(bot, "managers"):
        bot.managers = [manager]
    else:
        bot.managers.append(manager)

    # manager_load関数を実行する。(デフォルトでは何もしない)
    async with bot.pool.acquire() as conn:
        async with conn.cursor() as cursor:
            await manager.manager_load(cursor)
    return manager
