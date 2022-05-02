# Free RT - Data Manager

from __future__ import annotations

from typing import (
    TYPE_CHECKING, TypeVar, Literal, Union, Optional, NoReturn, Any, get_args
)

from collections import defaultdict
from asyncio import Event

from discord.ext import commands, tasks

from ujson import loads, dumps
from aiomysql import Cursor

if TYPE_CHECKING:
    from util import RT


Allocation = Union[Literal["Guild", "User", "Member", "Channel"], str]
Key = Optional[Union[str, int, Any]]
ALLOCATIONS = get_args(get_args(Allocation)[0])


class ChangedDict(dict):

    changed = False
    _new = False

    def __setitem__(self, key, value):
        self.changed = True
        return super().__setitem__(key, value)

    def __delitem__(self, key):
        self.changed = True
        return super().__delitem__(key)


class DataDict(defaultdict):

    _removed = []

    def __delitem__(self, key: str) -> None:
        self._removed.append(key)
        return super().__delitem__(key)

    def __setitem__(self, key: str, value: dict):
        if key in self._removed:
            self._removed.remove(key)
        return super().__setitem__(key, value)


TableSelfT = TypeVar("TableSelfT", bound="Table")


class Table:

    __allocation__: Optional[str] = None
    __key__: Optional[Key] = None

    def __init__(self, bot: RT, immediately_sync: bool = False, heritance: bool = False):
        assert self.__allocation__ is not None, "割り振りを設定してください。"
        self.immediately_sync = immediately_sync
        self.cog: DataManager = bot.cogs["DataManager"]
        self.bot = bot

        allocation = self.__allocation__.split()
        if len(allocation) == 1:
            allocation.append("BIGINT")
        self.__allocation_name__, self.__allocation_type__ = allocation

        self.name = self.__class__.__name__
        self.locked = Event()
        if heritance:
            self.locked.set()
        else:
            self.bot.dispatch("table_create", self)

    def __getattr__(self: TableSelfT, key: str) -> Any:
        if self.__key__:
            if key in ("pop", "update", "get", "items", "values", "keys"):
                return getattr(self.cog.data[self.name][self.__key__], key)
            elif key in self.__annotations__:
                return self.cog.data[self.name][self.__key__][key]
        raise AttributeError(key)

    def to_dict(self) -> dict:
        "このデータにある辞書を返します。この関数が返すものに値は書き込まないでください。"
        return self.cog.data[self.name] if self.__key__ is None \
            else self.cog.data[self.name][self.__key__]

    def sync(self):
        self.cog.sync(self.name)

    def _assert_key(self) -> Optional[NoReturn]:
        assert self.__key__ is not None, "キーが設定されていません。"

    def __setattr__(self, key: str, value: Any) -> None:
        if key in self.__annotations__:
            self._assert_key()
            new = self.__key__ not in self.cog.data[self.name]
            self.cog.data[self.name][self.__key__][key] = value
            if new:
                self.cog.data[self.name][self.__key__]._new = new
        else:
            return super().__setattr__(key, value)

    def __getitem__(self: TableSelfT, key: Key) -> TableSelfT:
        assert self.__key__ is None, "既にキーは設定されています。"
        new = self.__class__(self.bot, heritance=True)
        new.__key__ = key
        return new

    def __delitem__(self, key: Key) -> None:
        del self.cog.data[self.name][key]

    def __delattr__(self, key: str) -> None:
        if key in self.__annotations__:
            self._assert_key()
            del self.cog.data[self.name][self.__key__][key]
        else:
            return super().__delattr__(key)

    def __contains__(self, key: str) -> bool:
        if self.__key__ is None:
            return key in self.cog.data[self.name]
        else:
            return key in self.cog.data[self.name][self.__key__]


class DataManager(commands.Cog):
    def __init__(self, bot: RT):
        self.bot = bot
        self.data: defaultdict[str, DataDict[Key, ChangedDict]] = defaultdict(
            lambda: DataDict(ChangedDict)
        )
        self.allocations: dict[str, str] = {}
        self._loaded: list[str] = []
        self._auto_sync.start()

    @commands.Cog.listener()
    async def on_table_create(self, table: Table):
        # テーブルがないのなら作る。
        async with self.bot.mysql.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                if table.name not in self._loaded:
                    await cursor.execute(
                        f"""CREATE TABLE IF NOT EXISTS {table.name} (
                            {table.__allocation_name__} {table.__allocation_type__}, Data JSON
                        );"""
                    )
                # キャッシュを作る。
                self.allocations[table.name] = table.__allocation_name__
                await cursor.execute(f"SELECT * FROM {table.name};")
                for row in await cursor.fetchall():
                    if row:
                        self.data[table.name][row[0]] = ChangedDict(loads(row[1]))
                        self.data[table.name][row[0]].changed = False

        table.locked.set()

    def print(self, *args, **kwargs):
        return self.bot.print(f"[{self.__cog_name__}]", *args, **kwargs)

    async def _remove(
        self, cursor: Cursor, table: str, key: Key, print_: bool = False
    ) -> None:
        # 削除を行う。
        if print_:
            self.print("[sync.remove]", f"{table}.{key}")
        await cursor.execute(
            f"DELETE FROM {table} WHERE {self.allocations[table]} = %s;",
            (key,)
        )

    async def _update(
        self, cursor: Cursor, table: str, key: Key,
        data: ChangedDict, print_: bool = False
    ) -> None:
        # 更新を行う。
        if print_:
            self.print("[sync.update]", f"{table}.{key}: {data}")
        await cursor.execute(
            f"SELECT * FROM {table} WHERE {self.allocations[table]} = %s;",
            (key,)
        )
        if await cursor.fetchone():
            await cursor.execute(
                f"UPDATE {table} SET Data = %s WHERE {self.allocations[table]} = %s;",
                (dumps(data), key)
            )
        else:
            await cursor.execute(
                f"INSERT INTO {table} VALUES (%s, %s);", (key, dumps(data))
            )

    async def _sync(self, table: str, datas: DataDict[Key, ChangedDict]) -> None:
        # 指定されたテーブルのデータの同期を行います。
        self.print("[sync]", table)
        async with self.bot.mysql.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                # 削除されたものを消す。
                for removed_key in datas._removed:
                    await self._remove(cursor, table, removed_key)
                # 変更されたものをアップデートする。
                for key, data in list(datas.items()):
                    await self._update(cursor, table, key, data)
                    data.changed = False

    def sync(self, table: Optional[str] = None):
        "同期を行います。注意：キャッシュのデータが優先されます。"
        if table is None:
            if self.data[table]:
                self.bot.loop.create_task(
                    self._sync(table, self.data[table]), name=f"[{self.__cog_name__}] Sync: {table}"
                )
        else:
            if self.data:
                self.print("Now syncing...")
                for table, datas in list(self.data.items()):
                    self.bot.loop.create_task(
                        self._sync(table, datas), name=f"[{self.__cog_name__}] Sync: {table}"
                    )

    # @tasks.loop(seconds=10)
    @tasks.loop(minutes=10)
    async def _auto_sync(self):
        self.sync()

    def cog_unload(self):
        self._auto_save.cancel()

    @commands.Cog.listener()
    async def on_close(self, _):
        self.sync()

    async def test1(self):
        class DMTest(Table):
            __allocation__ = "GuildID"
            test: str
            index: int
        self.test = DMTest(self.bot)
        await self.test.locked.wait()

    async def test2(self):
        if "index" in self.test[1]:
            print(1)


async def setup(bot):
    await bot.add_cog(DataManager(bot))
