# Free RT Music - Player

from __future__ import annotations

from typing import TYPE_CHECKING, Union, Optional
from enum import Enum

from asyncio import Event
from random import sample

import discord

from util import sendableString

from .music import Music, is_url

if TYPE_CHECKING:
    from .__init__ import MusicCog


class NotAddedReason(Enum):
    "キューに追加することに失敗した際に呼ばれる関数です。"

    list_very_many = 1
    queue_many = 2


class LoopMode(Enum):
    "ループのモードの設定です。"

    none = 1
    all = 2
    one = 3


class Player:
    "音楽再生にサーバー毎に使う音楽プレイヤーのクラスです。"

    def __init__(self, cog: MusicCog, guild: discord.Guild, voice_client: discord.VoiceClient):
        self.cog, self.guild = cog, guild
        self.queues: list[Music] = []
        self._loop = LoopMode.none
        self.channel: Optional[discord.TextChannel] = None
        self.vc = voice_client
        self._volume, self._skipped = 1.0, False
        self._stopped = Event()
        self._stopped.set()
        self._closing = False

    def print(self, *args, **kwargs):
        "デバッグ用とかっこつけるためのprintです。"
        self.cog.print(f"[{self}]", *args, **kwargs)

    @property
    def length(self) -> int:
        "キューの長さを取得します。ただのエイリアス"
        return len(self.queues)

    async def add_from_url(self, author: discord.Member, url: str) -> Optional[
        Union[NotAddedReason, Exception, list[Music]]
    ]:
        "キューにURLから音楽を追加します。"
        if isinstance((data := await Music.from_url(
            self.cog, author, url, self.cog.max(self.guild)
        )), Exception):
            # 取得に失敗したのならエラーを起こす。
            return data
        elif isinstance(data, tuple):
            # もし取得結果が複数あるなら
            if not is_url(url):
                # もし検索結果が返ってきたのならそれをそのまま返す。
                return data[0]
            # 量制限の確認をする。
            if self.length + (queues_length := len(data[0])) > self.cog.max(author):
                return NotAddedReason.queue_many
            else:
                self.print("Adding %s queues, Author: %s" % (queues_length, author))
                self.queues.extend(data[0])
                if data[1]:
                    return NotAddedReason.list_very_many
        else:
            # 通常
            self.print("Adding queue: %s" % data)
            return self.add(data)

    def add(self, music: Music) -> Optional[NotAddedReason]:
        "渡されたMusicをqueueに追加します。"
        self.print("Adding queue: %s" % music)
        if self.length >= self.cog.max(self.guild):
            return NotAddedReason.queue_many
        else:
            self.queues.append(music)

    @property
    def now(self) -> Optional[Music]:
        "あるなら現在再生中のキューのMusicを返します。"
        self._assert_vc()
        if self.queues and self.vc:
            return self.queues[0]

    def _process_closed_queue(self):
        # 音楽再生終了後のキューの処理をする。
        if self.vc.is_connected() and not self._skipped:
            if self._loop == LoopMode.all:
                self.queues.append(self.queues.pop(0))
            elif self._loop == LoopMode.none:
                del self.queues[0]
        else:
            del self.queues[0]
            self._skipped = False

    async def _after_play(self, e: Exception):
        # 音楽再生終了後の後始末をする。
        self.print("Finished to play a music")

        if e and self.channel is not None:
            self.print("Error:", e)
            await self.channel.send(
                {"ja": f"何かしらエラーが発生して再生に失敗しました。\ncode: `{e}`",
                 "en": f"Something went wrong.\ncode: `{e}`"}
            )

        # 音源のお片付けをしてキューのcloseをしてキューを消す。
        self.print("Cleaning...")
        await self.queues[0].stop(self._process_closed_queue)

        self._stopped.set()

        # 次のキューがあれば再生を行う。
        if self.queues:
            await self.play()

    def _assert_vc(self):
        # VCに接続済みかチェックをします。
        assert self.vc is not None, "接続されていません。"

    async def play(self):
        """現在登録されているキューの一番最初にある曲を再生します。
        再生終了後にまだキューがある場合はもう一度この関数が呼ばれます。"""
        self._assert_vc()

        # キューを取って経過時間がわかるようにする。
        queue = self.queues[0]
        queue.start()
        # sourceを用意する。
        self.print("Loading music source...")
        source = await queue.make_source()
        # 音量を変更する。
        source.volume = self._volume

        self.print("Playing music...")
        self._stopped.clear()
        self.vc.play(
            source, after=lambda e: self.cog.bot.loop.create_task(
                self._after_play(e)
            )
        )

    def _assert_playing(self):
        assert self.vc.is_playing(), "現在は何も再生していません。"

    def pause(self) -> bool:
        "再生を一時停止します。二度目は再開します。"
        self._assert_vc()
        if self.now is not None:
            self.now.toggle_pause()
        if self.vc.is_paused():
            self.vc.resume()
            return True
        else:
            self._assert_vc()
            self.vc.pause()
            return False

    def skip(self):
        "次のキューにスキップします。"
        self._assert_playing()
        self._skipped = True
        self.vc.stop()

    @property
    def volume(self) -> float:
        """音量を取得します。パーセントで返されます。
        代入することで音量の変更することができます。"""
        return self._volume * 100

    @volume.setter
    def volume(self, volume: int):
        self._volume = volume / 100
        # もし音楽の再生中なら再生中のものの音量を変更する。
        if self.vc.is_playing():
            self.vc.source.volume = self._volume

    def shuffle(self):
        "キューをシャッフルします。"
        if self.queues:
            self.queues[1:] = sample(self.queues[1:], len(self.queues[1:]))

    def loop(self, mode: Optional[LoopMode] = None) -> LoopMode:
        "ループを設定します。"
        if mode is None:
            if self._loop == LoopMode.none:
                self._loop = LoopMode.one
            elif self._loop == LoopMode.one:
                self._loop = LoopMode.all
            else:
                self._loop = LoopMode.none
        else:
            self._loop = mode
        return self._loop

    async def wait_until_stopped(self) -> None:
        "再生が停止するまで待機をします。"
        await self._stopped.wait()

    async def disconnect(
        self, reason: Optional[sendableString] = None, force: bool = False
    ):
        "お片付けをして切断をします。"
        self._assert_vc()
        self.print("Disconnecting...")
        self._closing = True

        # キューが二個以上あるならキューを一個以外全部消す。
        if len(self.queues) > 1:
            self.queues = self.queues[:1]

        # 再生の停止をする。
        if self.vc.is_connected():
            await self.vc.disconnect(force=force)
        await self.wait_until_stopped()
        # もし理由があるなら送信しておく。
        if self.channel is not None and reason is not None:
            try: await self.channel.send(reason)
            except Exception: ...

        self.cog.bot.loop.call_soon(self.cog.remove_player, self.guild.id)

        self.print("Done")

    def __del__(self):
        if self.vc is not None and self.vc.is_connected():
            # 予期せずにこのクラスのインスタンスが消されたかつボイスチャンネルに接続してる場合は切断を行う。
            # 念の為のメモリリーク防止用のもの。
            self.cog.bot.loop.create_task(
                self.disconnect(
                    {"ja": "何らかの原因により再生が停止されました。",
                     "en": "Something went wrong when playing a music."}
                ), name=f"{self}.disconnect"
            )

    def __str__(self):
        return f"<Player Guild={self.guild} now={self.now}>"
