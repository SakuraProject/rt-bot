# Free RT AutoMod - Cache

from typing import TYPE_CHECKING, Optional, Any, Dict, List

import discord

from time import time

from .modutils import join

if TYPE_CHECKING:
    from .__init__ import AutoMod


class Cache:
    "スパム検知度等のキャッシュ兼ユーザーデータクラスです。"

    # アノテーションをクラスにつけているものはUserDataです。
    warn: float = 0.0
    last_update: float

    # キャッシュのタイムアウト
    TIMEOUT = 180
    # あやしいレベルのマックスで`suspicious`がこれになると1警告数が上がる。
    MAX_SUSPICIOUS = 150

    def __init__(
        self, cog: "AutoMod", member: discord.Member,
        guild: discord.Guild, data: dict
    ):
        self.guild, self.member, self.cog = guild, member, cog
        self.require_save = False
        self.update_timeout()
        # 初期状態のデータを書き込む。アノテーションがついている変数に書き込まれるべきです。
        for key in data:
            setattr(self, key, data[key])
        self.last_update = time()
        # 以下以降スパムチェックに使うキャッシュの部分です。
        self.before: Optional[discord.Message] = None
        self.before_content: Optional[discord.Message] = None
        self.before_join: Optional[float] = None
        self.suspicious = 0

    def process_suspicious(self) -> bool:
        "怪しさがMAXかどうかをチェックします。もしMAXならリセットします。"
        if self.suspicious >= self.MAX_SUSPICIOUS:
            self.suspicious = 0
            self.warn += 1
            self.cog.print("[warn.up]", self)
            return True
        return False

    def update_cache(self, message: discord.Message):
        "キャッシュをアップデートします。"
        self.update_timeout()
        before = self.before
        self.before_content = join(self.before or message)
        self.before = message
        return before

    def update_timeout(self):
        "タイムアウトを更新します。"
        self.checked = time()
        self.timeout = self.checked + self.TIMEOUT

    def keys(self) -> List[str]:
        "このデータクラスにあるキーのリストを返します。"
        return list(self.__annotations__.keys())

    def values(self) -> List[Any]:
        "このデータクラスにある値のリストを返します。"
        return [getattr(self, name) for name in self.keys()]

    def items(self) -> Dict[str, Any]:
        "このデータクラスにあるデータを辞書で返します。"
        return {key: value for key, value in zip(self.keys(), self.values())}

    def update(self, data: "Cache"):
        "このデータクラスにあるデータを更新します。"
        for key, value in data.items():
            setattr(self, key, value)

    def __setattr__(self, key, value):
        if key in self.__annotations__:
            # もしセーブデータが書き換えられたのなら更新が必要とする。最終更新日も更新をする。
            if key != "last_update":
                self.require_save = True
                self.last_update = time()
        return super().__setattr__(key, value)

    def __str__(self):
        return f"<AutoModCache member={self.member} UserData={self.items()} " \
            f"suspicious={self.suspicious} require_save={self.require_save}>"
