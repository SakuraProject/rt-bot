# Free RT AutoMod - Data Manager

from typing import TYPE_CHECKING, NewType, TypedDict, Literal, Union, Optional, Dict, Tuple, List

from discord.ext import tasks
import discord

from ujson import loads, dumps
from aiomysql import Cursor
from time import time

from util import DatabaseManager

from .cache import Cache

if TYPE_CHECKING:
    from .__init__ import AutoMod


Warn = NewType("Warn", float)


class GuildData(TypedDict, total=False):
    "GuildDataの辞書の型です。"

    ban: Warn
    mute: Warn
    invites: NewType("invites", List[int])
    ignore: List[int]
    bolt: float
    invite_deleter: NewType("invite_deleter", List[str])
    emoji: int


class HashableGuild(dict):
    "GuildDataの辞書用のクラスです。hashで使用可能かつデータ変更時に`require_save`が`True`になるようになっています。"

    guild_id: int = 0
    require_save: bool = False

    def __init__(self, guild_id: int, *args, **kwargs):
        self.guild_id = guild_id
        super().__init__(*args, **kwargs)

    def __hash__(self):
        return self.guild_id

    def __setitem__(self, key, value):
        self.require_save = True
        return super(HashableGuild, self).__setitem__(key, value)

    def __delitem__(self, key):
        self.require_save = True
        return super(HashableGuild, self).__delitem__(key)


UserData = Dict[int, Cache]
SaveData = Tuple[Union[GuildData, HashableGuild], Dict[int, UserData]]
Guild = Union[int, discord.Guild]


class DataManager(DatabaseManager):
    "セーブデータ管理用クラス"

    TABLES = ("AutoModData",)
    DEFAULTS = {
        "ban": 5, "mute": 3, "bolt": 60, "emoji": 15
    }
    WARN_RESET_TIMEOUT = 86400

    def __init__(self, cog: "AutoMod"):
        self.cog, self.pool = cog, cog.bot.mysql.pool
        self._update_database.start()
        self.cog.bot.loop.create_task(self._prepare_table())

    async def _prepare_table(self, cursor: Cursor = None):
        await cursor.execute(
            f"""CREATE TABLE IF NOT EXISTS {self.TABLES[0]} (
                GuildID BIGINT PRIMARY KEY NOT NULL, GuildData JSON, UserData JSON
            );"""
        )
        await cursor.execute(f"SELECT GuildID FROM {self.TABLES[0]};")
        for row in await cursor.fetchall():
            if row:
                self.cog.enabled.append(row[0])

    @tasks.loop(seconds=10)
    # @tasks.loop(seconds=30)
    async def _update_database(self):
        # 古いキャッシュの削除とセーブをするループです。
        now = time()
        for guild_id in list(self.cog.caches.keys()):
            if self.cog.caches[guild_id][0].require_save:
                # もしGuildDataがセーブを必要としているならセーブする。
                self.cog.print("[save.GuildData]", guild_id)
                await self.save_guild_data(guild_id, self.cog.caches[guild_id][0])
                self.cog.caches[guild_id][0].require_save = False
            for member_id in list(self.cog.caches[guild_id][1].keys()):
                if self.cog.caches[guild_id][1][member_id].require_save:
                    # UserDataがセーブを必要としているならセーブをする。
                    self.cog.print("[save.UserData]", member_id)
                    await self.save_user_data(self.cog.caches[guild_id][1][member_id])
                    self.cog.caches[guild_id][1][member_id].require_save = False
                if self.cog.caches[guild_id][1][member_id].timeout <= now:
                    # もしタイムアウト(放置されている)キャッシュがあるなら消す。
                    del self.cog.caches[guild_id][1][member_id]
                if not self.cog.caches[guild_id][1]:
                    # もしサーバーのキャッシュが空になったらそれもいらないので消す。
                    del self.cog.caches[guild_id]

        self.cog.bot.loop.create_task(self._reset_warn(now))

    def close(self):
        "コグアンロード時に呼び出されるべき関数です。"
        self._update_database.cancel()

    async def _reset_warn(self, now: float, cursor: Cursor = None) -> None:
        "一日以上アップデートされていない警告数をリセットする。"
        await cursor.execute(f"SELECT * FROM {self.TABLES[0]};")
        for row in await cursor.fetchall():
            if not row:
                continue
            data = self.get_classed(
                row[0], *map(loads, row[1:])
            )
            if data is None:
                continue
            for data in data[1].values():
                if not hasattr(data, "last_update"):
                    continue
                if (now - data.last_update >= self.WARN_RESET_TIMEOUT
                        and data.warn > 0):
                    self.cog.print("[warn.reset]", data.member.id)
                    data.warn = 0
                    await self._save_user_data(cursor, data)
                    # もしキャッシュされているUserDataがあればそれを削除する。
                    if (row[0] in self.cog.caches
                            and data.member.id in self.cog.caches[row[0]][1]):
                        del self.cog.caches[row[0]][1][data.member.id]

    async def toggle_automod(self, guild_id: int, cursor: Cursor = None) -> bool:
        "AutoModのOnOffを切り替えます。"
        if guild_id in self.cog.enabled:
            await cursor.execute(
                f"DELETE FROM {self.TABLES[0]} WHERE GuildID = %s;", (guild_id,)
            )
            self.cog.enabled.remove(guild_id)
            return False
        else:
            await cursor.execute(
                f"INSERT INTO {self.TABLES[0]} VALUES (%s, %s, %s);", (
                    guild_id, r"{}", r"{}"
                )
            )
            self.cog.enabled.append(guild_id)
            return True

    def if_str_loads(self, data: Union[str, dict]) -> dict:
        if isinstance(data, str):
            data = loads(data)
        return data

    def get_classed(
        self, guild: Guild, guild_data: Union[str, dict], user_data: Union[str, dict]
    ) -> Optional[Tuple[GuildData, Dict[int, Cache]]]:
        "渡されたGuildDataとUserDataの辞書をAutoModのプログラムで使える状態にします。"
        guild_data, user_data = self.if_str_loads(guild_data), \
            self.if_str_loads(user_data)
        if isinstance(guild, int):
            guild = self.cog.bot.get_guild(guild)
        if guild is not None:
            return HashableGuild(guild.id, guild_data), {
                key: Cache(self.cog, guild.get_member(int(key)), guild, user_data[key])
                for key in user_data
            }

    async def _read(self, cursor, guild) -> Optional[SaveData]:
        # セーブデータを読み込む関数です。
        await cursor.execute(
            f"SELECT GuildData, UserData FROM {self.TABLES[0]} WHERE GuildID = %s;",
            getattr(guild, "id", guild)
        )
        if (row := await cursor.fetchone()):
            return self.get_classed(guild, *map(loads, row))
        else:
            return HashableGuild(guild.id, {}), {}

    async def read(self, guild: Guild, cursor: Cursor = None) -> Optional[SaveData]:
        "セーブデータを読み込みます。"
        return await self._read(cursor, guild)

    def dump_user_datas(self, datas: Dict[int, Cache]) -> str:
        "複数のUserDataをdumpします。"
        return dumps({
            key: value.items() for key, value in datas.items()
        })

    def _get_save_data_query(self, mode: Literal["GuildData", "UserData"]) -> str:
        return f"""INSERT INTO {self.TABLES[0]} VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE {mode} = %s;"""

    async def _save_user_data(self, cursor, data):
        # UserDataをセーブします。
        if data.member is not None:
            guild_data, currents = await self._read(cursor, data.guild)
            if data.member.id in currents:
                currents[data.member.id].update(data)
            else:
                currents[data.member.id] = data
            await cursor.execute(
                self._get_save_data_query("UserData"),
                (
                    data.guild.id, dumps(guild_data), (
                        currents := self.dump_user_datas(currents)
                    ), currents
                )
            )

    async def save_user_data(self, data: Cache, cursor: Cursor = None) -> None:
        "UserDataをセーブします。"
        await self._save_user_data(cursor, data)

    async def save_guild_data(
        self, guild: Guild, data: GuildData, cursor: Cursor = None
    ) -> None:
        "GuildDataをセーブします。"
        current, currents = await self._read(cursor, guild)
        current.update(data)
        await cursor.execute(
            self._get_save_data_query("GuildData"),
            (
                getattr(guild, "id", guild), (current := dumps(current)),
                self.dump_user_datas(currents), current
            )
        )

    async def prepare_cache_guild(self, guild: discord.Guild) -> None:
        "サーバーのキャッシュを用意します。"
        if guild.id not in self.cog.caches:
            self.cog.caches[guild.id] = await self.read(guild)

    async def prepare_cache_member(self, member: discord.Member) -> None:
        "メンバーのキャッシュを用意します。"
        if member.id not in self.cog.caches[member.guild.id][1]:
            _, currents = await self.read(member.guild)
            self.cog.caches[member.guild.id][1][member.id] = currents.get(
                member.id, Cache(self, member, member.guild, {})
            )
