# Free RT Music - Music Data class

from __future__ import annotations

from typing import (
    TypedDict, Callable, Literal, Union, Optional, Any
)

from time import time

import discord
from jishaku.functools import executor_function

from niconico import NicoNico, objects as niconico_objects
from youtube_dl import YoutubeDL
from requests import get
import urllib.parse
import urllib.request

if __name__ == "__main__":
    from .__init__ import MusicCog


#   youtube_dl用のオプションの辞書
# 音楽再生時に使用するオプション
NORMAL_OPTIONS = {
    "format": "bestaudio/best",
    "default_search": "auto",
    "logtostderr": False,
    "cachedir": False,
    "ignoreerrors": True,
    "source_address": "0.0.0.0",
    "cookiefile": "data/youtube-cookies.txt"
}
# 音楽情報取得に使うオプション
FLAT_OPTIONS = {
    "extract_flat": True,
    "source_address": "0.0.0.0",
    "cookiefile": "data/youtube-cookies.txt"
}


#   FFmpeg用の再接続するようにするためのオプション
FFMPEG_BEFORE_OPTIONS = "-reconnect 1 -reconnect_streamed 1 -reconnect_delay_max 5"
FFMPEG_OPTIONS = "-vn"


#   型等
class MusicTypes:
    "何のサービスの音楽かです。"

    niconico = 1
    youtube = 2
    soundcloud = 3
    spotify = 4
    ysmfilm = 5


class MusicDict(TypedDict):
    "プレイリスト等に保存する際の音楽データの辞書の型です。"

    music_type: int
    title: str
    url: str
    thumbnail: str
    duration: Optional[int]
    extras: Any


#   Utils
def yf_gettitle(id):
    searchurl = "https://ysmfilm.wjg.jp/view_raw.php?id=" + id
    with urllib.request.urlopen(searchurl) as ut:
        tit = ut.read().decode()
    return tit


def yf_getduration(id):
    searchurl = "https://ysmfilm.wjg.jp/duration.php?id=" + id
    with urllib.request.urlopen(searchurl) as ut:
        tit = ut.read().decode()
    return tit


niconico = NicoNico()


def make_niconico_music(
    cog: MusicCog, author: discord.Member, url: str, video: Union[
        niconico_objects.Video, niconico_objects.MyListItemVideo
    ]
) -> Music:
    "ニコニコ動画のMusicクラスのインスタンスを用意する関数です。ただのエイリアス"
    return Music(
        cog, author, MusicTypes.niconico, video.title, url,
        video.thumbnail.url, video.duration
    )


def get_music_by_ytdl(url: str, mode: Literal["normal", "flat"]) -> dict:
    "YouTubeのデータを取得する関数です。ただのエイリアス"
    return YoutubeDL(globals()[f"{mode.upper()}_OPTIONS"]).extract_info(url, download=False)


def make_youtube_url(data: dict) -> str:
    "渡された動画データからYouTubeの動画URLを作ります。"
    return f"""https://www.youtube.com/watch?v={
        data.get("display_id", data.get("id", "3JW1qw7HB5U"))
    }"""


def format_time(time_: Union[int, float]) -> str:
    "経過した時間を`01:39`のような`分：秒数`の形にフォーマットする。"
    return ":".join(
        map(lambda o: (
            str(int(o[1])).zfill(2)
            if o[0] or o[1] <= 60
            else format_time(o[1])
        ), ((0, time_ // 60), (1, time_ % 60)))
    )


def is_url(url: str) -> bool:
    "URLかどうかをチェックします。ただのエイリアス"
    return url.startswith(("http://", "https://"))


#   メインディッシュ
class Music:
    "音楽のデータを格納するためのクラスです。"

    on_close: Callable[..., Any]
    """音楽再生終了後に呼び出すべき関数です。
    ニコニコ動画の音楽を再生した場合は再生終了後にこれを呼び出してください。"""

    def __init__(
        self, cog: MusicCog, author: discord.Member, music_type: int, title: str,
        url: str, thumbnail: str, duration: Union[int, None], extras: Any = {}
    ):
        self.extras, self.title, self.url = extras, title, url
        self.thumbnail, self.duration = thumbnail, duration
        self.music_type, self.cog, self.author = music_type, cog, author

        self._start, self._stop = 0.0, 0.0
        self._made_source = False
        self.closed = False

        self.on_close = lambda: None

    def to_dict(self) -> MusicDict:
        "このクラスに格納されているデータをJSONにシリアライズ可能な辞書にします。"
        return MusicDict(
            music_type=self.music_type, title=self.title, url=self.url,
            thumbnail=self.thumbnail, duration=self.duration, extras=self.extras
        )

    @classmethod
    def from_dict(cls, cog: MusicCog, author: discord.Member, data: MusicDict) -> Music:
        "MusicDictに準拠した辞書からMusicクラスのインスタンスを作成します。"
        return cls(cog, author, **data)

    @classmethod
    async def from_url(
        cls, cog: MusicCog, author: discord.Member, url: str, max_result: int
    ) -> Union[Music, tuple[list[Music], bool], Exception]:
        """音楽を取得します。
        ニコニコ動画のマイリストやYouTubeの再生リストを渡した場合はそのリストと最大取得数でカンストしたかどうかのタプルが返されます。
        取得に失敗した場合はエラーが返されます。"""
        result = await cls._from_url(cls, cog, author, url, max_result)
        if isinstance(result, str):
            # もしプレイリストのURLが返ってきたのならもう一度呼び出す。
            return await cls._from_url(cls, cog, author, result, max_result)
        return result

    @staticmethod
    @executor_function
    def _from_url(cls, cog, author, url, max_result):
        try:
            if "nicovideo.jp" in url or "nico.ms" in url:
                # ニコニコ動画
                if "mylist" in url:
                    # マイリストの場合
                    items, length, count_stop = [], 0, True
                    for mylist in niconico.video.get_mylist(url):
                        length += len(mylist.items)
                        items.extend([
                            make_niconico_music(
                                cog, author, item.video.url, item.video
                            )
                            for item in mylist.items
                        ])
                        if length > max_result:
                            items = items[:max_result]
                            break
                    else:
                        count_stop = False
                    return items, count_stop
                # マイリストではなく通常の動画の場合
                video = niconico.video.get_video(url)
                return make_niconico_music(cog, author, video.url, video.video)
            elif "soundcloud.com" in url or "soundcloud.app.goo.gl" in url:
                if "goo" in url:
                    # 短縮URLの場合はリダイレクト先が本当の音楽のURLなのでその真のURLを取得する。
                    url = get(url).url
                data = get_music_by_ytdl(url, "flat")
                return cls(
                    cog, author, MusicTypes.soundcloud, data["title"], url,
                    data["thumbnail"], data["duration"]
                )
            elif "ysmfilm" in url:
                qs = urllib.parse.urlparse(url).query
                qs_d = urllib.parse.parse_qs(qs)
                return cls(
                    cog, author, MusicTypes.ysmfilm, yf_gettitle(qs_d['id'][0]), url,
                    "https://ysmfilm.wjg.jp/th.php?id=" + qs_d['id'][0],
                    int(yf_getduration(qs_d['id'][0]).split(':')[0]) * 360
                    + int(yf_getduration(qs_d['id'][0]).split(':')[1]) * 60
                    + int(yf_getduration(qs_d['id'][0]).split(':')[2])
                )
            else:
                # YouTube
                if not is_url(url):
                    # 検索の場合はyoutube_dlで検索をするためにytsearchを入れる。
                    url = f"ytsearch15:{url}"

                data = get_music_by_ytdl(url, "flat")
                if data.get("entries"):
                    # 再生リストなら
                    items = []
                    for count, entry in enumerate(data["entries"], 0):
                        if count == max_result:
                            return items, True
                        items.append(
                            cls(
                                cog, author, MusicTypes.youtube, entry["title"],
                                make_youtube_url(entry),
                                f"http://i3.ytimg.com/vi/{entry['id']}/hqdefault.jpg",
                                entry["duration"]
                            )
                        )
                    else:
                        return items, False

                if "thumbnail" in data:
                    # 通常の動画なら
                    return cls(
                        cog, author, MusicTypes.youtube, data["title"],
                        make_youtube_url(data), data["thumbnail"], data["duration"]
                    )
                else:
                    return data["url"]
        except Exception as e:
            cog.print("Failed to load music: %s: %s" % (e, url))
            return e

    @executor_function
    def _prepare_source(self) -> str:
        "音楽再生に使う動画の直URLの準備をします。"
        if self.music_type in (MusicTypes.youtube, MusicTypes.soundcloud):
            return get_music_by_ytdl(self.url, "normal")["url"]
        elif self.music_type == MusicTypes.niconico:
            self.video = niconico.video.get_video(self.url)
            self.video.connect()
            setattr(self, "on_close", self.video.close)
            return self.video.download_link
        elif self.music_type == MusicTypes.ysmfilm:
            qs = urllib.parse.urlparse(self.url).query
            qs_d = urllib.parse.parse_qs(qs)
            return "https://ysmfilm.wjg.jp/video/" + qs_d['id'][0] + ".mp4"
        assert False, "あり得ないことが発生しました。"

    async def make_source(self) -> Union[
        discord.PCMVolumeTransformer, discord.FFmpegOpusAudio
    ]:
        "音楽再生のソースのインスタンスを作ります。"
        self._made_source = True
        if discord.opus.is_loaded():
            # 通常
            return discord.PCMVolumeTransformer(
                discord.FFmpegPCMAudio(
                    await self._prepare_source(), before_options=FFMPEG_BEFORE_OPTIONS,
                    options=FFMPEG_OPTIONS
                )
            )
        else:
            # もしOpusライブラリが読み込まれていないのならFFmpegにOpusの処理をしてもらう。
            # その代わり音量調整はできなくなる。(本番環境ではここは実行されないのでヨシ！)
            return discord.FFmpegOpusAudio(await self._prepare_source())

    def start(self) -> None:
        "途中経過の計算用の時間を計測を開始する関数です。"
        self._start = time()

    def toggle_pause(self):
        "途中経過の時間の計測を停止させます。また、停止後に実行した場合は計測を再開します。"
        if self._stop == 0.0:
            self._stop = time()
        else:
            self._start += self._stop - self._start
            self._stop = 0.0

    @executor_function
    def stop(self, callback: Callable[..., Any] = None) -> None:
        "音楽再生終了時に実行すべき関数です。"
        if self._made_source:
            self.closed = True
            if self._stop != 0.0:
                self.toggle_pause()
            self.on_close()
            if callback is not None:
                callback()

    @property
    def marked_title(self) -> str:
        "マークダウンによるURLリンク済みのタイトルの文字列を返します。"
        return f"[{self.title}]({self.url})"

    @property
    def now(self) -> float:
        "何秒再生してから経過したかです。"
        return time() - self._start

    @property
    def formated_now(self) -> str:
        "フォーマット済みの経過時間です。"
        return format_time(self.now)

    @property
    def formated_duration(self) -> Optional[str]:
        "フォーマット済みの動画の時間です。"
        if self.duration is not None:
            return format_time(self.duration)

    @property
    def elapsed(self) -> str:
        "何秒経過したかの文字列です。`/`"
        return f"{self.formated_now}/{self.formated_duration or '??:??'}"

    def make_seek_bar(self, length: int = 15) -> str:
        "どれだけ音楽が再生されたかの絵文字によるシークバーを作る関数です。"
        if self.duration is None:
            return ""
        return "".join((
            (base := "?" * length
             )[:(now := int(self.now / self.duration * length))],
            "?", base[now:])
        )

    def _init_start(self):
        if self._start == 0.0:
            self.start()

    def __str__(self):
        self._init_start()
        return f"<Music title={self.title} elapsed={self.elapsed} author={self.author}>"

    def __del__(self):
        # もし予期せずにこのクラスのインスタンスが削除された際には終了処理をする。
        if not self.closed and self._made_source:
            self.cog.bot.loop.create_task(self.stop())

    def make_embed(self, seek_bar: bool = False) -> discord.Embed:
        "再生中の音楽を示す埋め込みを作成します。"
        embed = discord.Embed(title="Now playing", color=self.cog.bot.Colors.normal)
        if seek_bar:
            embed.description = self.make_seek_bar()
        embed.add_field(name="Title", value=self.marked_title)
        self._init_start()
        embed.add_field(name="Time", value=self.elapsed)
        embed.set_thumbnail(url=self.thumbnail)
        embed.set_author(name=self.author.name, icon_url=getattr(self.author.avatar, "url", ""))
        return embed
