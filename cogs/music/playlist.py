# Free RT Music - Playlist

from __future__ import annotations

from typing import TYPE_CHECKING, Union, Optional

import discord

from .music import Music, MusicDict

if TYPE_CHECKING:
    from .__init__ import MusicCog


def to_musics(data: list[MusicDict], cog: MusicCog, author: discord.Member) -> list[Music]:
    return [Music.from_dict(cog, author, data) for data in data]

class Playlist:
    "プレイリストのクラスです。"

    def __init__(self, data: list[MusicDict], max_: int):
        self.data, self.max_ = data, max_

    def _convert(self, music: Union[Music, MusicDict]) -> MusicDict:
        if isinstance(music, Music):
            music = music.to_dict()
        return music

    @property
    def length(self):
        "プレイリストにある曲の数を返します。ただのエイリアス"
        return len(self.data)

    def to_musics(self, cog: MusicCog, author: discord.Member) -> list[Music]:
        "全てをMusicにしたリストを返します。"
        return to_musics(self.data, cog, author)

    def add(self, music: Union[Music, MusicDict], length: Optional[int] = None) -> None:
        "プレイリストに音楽を追加します。"
        assert (length or self.length) < self.max_, {
            "ja": "これ以上追加できません。", "en": f"You can't add more than {self.max_}."
        }
        self.data.append(self._convert(music))

    def extend(self, musics: list[Union[Music, MusicDict]]) -> None:
        "プレイリストにMusicのリストを追加します。"
        length = self.length
        for music in musics:
            self.add(music, length)

    def remove(self, music: Union[Music, MusicDict]) -> bool:
        "プレイリストからMusicを削除します。"
        music = self._convert(music)
        for index in range(self.data):
            if (self.data[index]["url"] == music["url"]
                    or self.data[index]["title"] == music["title"]):
                del self.data[index]
                return True
        return False

    def removes(self, musics: list[Union[Music, MusicDict]]) -> None:
        "プレイリストからMusicのリストを消します。"
        for music in musics:
            self.remove(music)