# RT Util - Data Manager

from collections.abc import Callable, Coroutine

from inspect import iscoroutinefunction, signature, Parameter
from functools import wraps

from aiomysql import Cursor


class _Dummy:
    default = Parameter.empty


class DatabaseManager:
    def __init_subclass__(cls):
        for key in dir(cls):
            coro: Callable[..., Coroutine] = getattr(cls, key)
            if iscoroutinefunction(coro):
                if (
                    "cursor" in coro.__annotations__
                    and not signature(coro).parameters.get("cursor", _Dummy).default
                    == _Dummy.default
                ):
                    setattr(cls, coro.__name__, cls.wrap(coro))

    @staticmethod
    def wrap(coro: Callable[..., Coroutine]) -> Callable[..., Coroutine]:
        "自動的にCursorがキーワード引数に渡されるようにするデコレータです。"

        @wraps(coro)
        async def new_coro(self, *args, **kwargs):
            selfmade = "cursor" not in kwargs and not any(
                isinstance(arg, Cursor) for arg in args
            )
            if selfmade:
                conn = await self.pool.acquire()
                kwargs["cursor"] = await conn.cursor()
            try:
                data = await coro(self, *args, **kwargs)
            except Exception as e:
                if selfmade:
                    await kwargs["cursor"].close()
                    self.pool.release(conn)
                raise e
            finally:
                if selfmade:
                    await kwargs["cursor"].close()
                    self.pool.release(conn)
            return data

        return new_coro
