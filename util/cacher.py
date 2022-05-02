# Free RT - Cacher, キャッシュ管理

from __future__ import annotations

from typing import Generic, TypeVar, Any, Optional
from collections.abc import Iterator, Callable

from time import time

from discord.ext import tasks


DataT = TypeVar("DataT")


class Cache(Generic[DataT]):
    "キャッシュのデータを格納するためのクラスです。"

    def __init__(self, data: DataT, deadline: float):
        self.data, self.deadline = data, deadline

    def is_dead(self, time_: Optional[float] = None) -> bool:
        "死んだキャッシュかどうかをチェックします。"
        return (time_ or time()) > self.deadline

    def __str__(self) -> str:
        return f"<Cache data={type(self.data)} deadline={self.deadline}>"

    def __repr__(self) -> str:
        return str(self)


KeyT, ValueT = TypeVar("KeyT"), TypeVar("ValueT")


class Cacher(Generic[KeyT, ValueT]):
    "キャッシュを管理するためのクラスです。\n注意: CacherPoolと兼用しないとデータは自然消滅しません。"

    def __init__(self, lifetime: float, default: Optional[Callable[[], Any]] = None):
        self.data: dict[KeyT, Cache[ValueT]] = {}
        self.lifetime, self.default = lifetime, default

        self.get, self.pop = self.data.get, self.data.pop
        self.keys = self.data.keys

    def set(self, key: KeyT, data: ValueT, lifetime: Optional[float] = None) -> None:
        "値を設定します。\n別のライフタイムを指定することができます。"
        self.data[key] = Cache(data, time() + (lifetime or self.lifetime))

    def __contains__(self, key: KeyT) -> bool:
        return key in self.data

    def _default(self, key: KeyT):
        if self.default is not None and key not in self.data:
            self.set(key, self.default())

    def __getitem__(self, key: KeyT) -> ValueT:
        self._default(key)
        return self.data[key].data

    def __getattr__(self, key: KeyT) -> ValueT:
        return self[key]

    def __delitem__(self, key: KeyT) -> None:
        del self.data[key]

    def __delattr__(self, key: KeyT) -> None:
        del self[key]

    def __setitem__(self, key: KeyT, value: ValueT) -> None:
        self.set(key, value)

    def values(self, mode_list: bool = False) -> Iterator[ValueT]:
        for value in list(self.data.values()) if mode_list else self.data.values():
            yield value.data

    def items(self, mode_list: bool = False) -> Iterator[tuple[KeyT, ValueT]]:
        for key, value in list(self.data.items()) if mode_list else self.data.items():
            yield (key, value.data)

    def get_raw(self, key: KeyT) -> Cache[ValueT]:
        "データが格納されたCacheを取得します。"
        self._default(key)
        return self.data[key]

    def __str__(self) -> str:
        return f"<Cacher data={type(self.data)} defaultLifetime={self.lifetime}>"

    def __repr__(self) -> str:
        return str(self)


class CacherPool:
    "Cacherのプールです。"

    def __init__(self):
        self.cachers: list[Cacher] = []
        self._cache_remover.start()

    def acquire(self, lifetime: float, default: Optional[Callable[[], Any]] = None) -> Cacher:
        "Cacherを生み出します。"
        self.cachers.append(Cacher(lifetime, default))
        return self.cachers[-1]

    def release(self, cacher: Cacher) -> None:
        "指定されたCacherを削除します。"
        self.cachers.remove(cacher)

    @tasks.loop(seconds=5)
    async def _cache_remover(self):
        now = time()
        for cacher in self.cachers:
            for key, value in list(cacher.data.items()):
                if value.is_dead(now):
                    del cacher[key]

    def __del__(self):
        if self._cache_remover.is_running():
            self._cache_remover.cancel()
