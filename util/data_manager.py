# Free RT Util - Data Manager

from collections.abc import Callable, Coroutine

from inspect import iscoroutinefunction, signature, Parameter
from functools import wraps

from aiomysql import Cursor


class _Dummy:
    default = Parameter.empty


class DatabaseManager:
    # データベースマネージャー。現在は昔のrtutilのものを流用。
    def __init_subclass__(cls):
        # クラスが継承されたときに呼び出される。
        for key in dir(cls):
            coro: Callable[..., Coroutine] = getattr(cls, key)
            if iscoroutinefunction(coro):  # コルーチン関数(async def)であれば
                if ("cursor" in coro.__annotations__ and 
                        not signature(coro).parameters.get("cursor", _Dummy).default == _Dummy.default):
                    # cursor引数があれば、自動でデコレータを付ける
                    setattr(cls, coro.__name__, cls.wrap(coro))

    @staticmethod
    def wrap(coro: Callable[..., Coroutine]) -> Callable[..., Coroutine]:
        "自動的にCursorがキーワード引数に渡されるようにするデコレータです。"
        @wraps(coro)
        async def new_coro(self, *args, **kwargs):
            selfmade = "cursor" not in kwargs and not any(isinstance(arg, Cursor) for arg in args)
            if selfmade:
                # connectionとcursorを作成してkwargsに渡す。
                conn = await self.pool.acquire()
                kwargs["cursor"] = await conn.cursor()
            try:
                data = await coro(self, *args, **kwargs)
            except Exception as e:
                if selfmade:
                    # 自動でcursorを閉じ、releaseする。
                    await kwargs["cursor"].close()
                    self.pool.release(conn)
                raise e
            finally:
                if selfmade:
                    # 自動でcursorを閉じ、releaseする。
                    await kwargs["cursor"].close()
                    self.pool.release(conn)
            return data
        return new_coro
