# RT TTS - Agents

from __future__ import annotations

from typing import Literal, Union, Optional
from enum import Enum

from subprocess import Popen, TimeoutExpired, PIPE
from asyncio import get_running_loop
from os.path import exists

from re import sub, findall

import discord

from jishaku.functools import executor_function

from pyopenjtalk import g2p
from gtts import gTTS

from aiofiles import open as aioopen
from aiohttp import ClientSession
from bs4 import BeautifulSoup
from ujson import load, dumps


ENG2KANA_DATA_PATH = "cogs/tts/data/eng2kana.json"
"英語からカタカナに変換されている辞書があるJSONファイルです。"
AQUESTALK_DIRECTORY = "cogs/tts/lib/AquesTalk"
"AquesTalkのプログラムが入っているフォルダです。"
ALLOWED_CHARACTERS_CSV = "cogs/tts/data/allowed_characters.csv"
"AquesTalkで読み上げ可能な文字が入っているcsvファイルです。"
OPENJTALK = "open_jtalk"
"なんのコマンドでOpenJTalkを実行するかです。"
OPENJTALK_DICTIONARY = "cogs/tts/lib/OpenJTalk/dic"
"OpenJTalkで使う辞書がある場所です。"
OPENJTALK_VOICE_DIRECTORY = "cogs/tts/lib/OpenJTalk"
"OpenJTalkで使う音声のデータがあるディレクトリです。"
AGENTS_JSON = "cogs/tts/data/avaliable_voices.json"
"使用可能な音声の情報が書いてあるJSONファイルのパスです。"
AGENTS: dict[str, Agent] = {}
"使用可能なAgentの辞書です。"


class VoiceTypes(Enum):
    "音声合成に使うものの列挙型です。"

    openjtalk = 1
    aquestalk = 2
    gtts = 3


with open(ALLOWED_CHARACTERS_CSV, "r",encoding="utf8") as f:
    ALLOWED_CHARACTERS = tuple(f.read().split())
    "AquesTalkで使える文字のタプル"
Source = Union[discord.FFmpegOpusAudio, discord.FFmpegPCMAudio]

# 英語とカタカナの辞書を読み込んでおく。
eng2kanaData: dict[str, str] = {}
if exists(ENG2KANA_DATA_PATH):
    with open(ENG2KANA_DATA_PATH, "r") as f:
        eng2kanaData.update(load(f))
else:
    # 存在しないなら空のものを作っておく。
    with open(ENG2KANA_DATA_PATH, "w") as f:
        f.write(r"{}")


async def _dumps_eng2kana_data():
    # eng2kanaのデータを保存します。
    async with aioopen(ENG2KANA_DATA_PATH, "w") as f:
        await f.write(dumps(eng2kanaData, indent=2, ensure_ascii=False))


HEADERS = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0'}
"英語をカタカナに変換するのに使うウェブサイトへアクセスするのに使うヘッダー"
session, loop = None, None
async def eng2kana(text: str) -> str:
    "渡された文字列にある英語をかなにします。"
    global session, loop
    if session is None:
        session = ClientSession(
            loop=(loop := get_running_loop()), raise_for_status=True
        )

    text = text.replace("\n", "、").lower()

    # 英単語をカタカナにする。
    words = findall("[a-zA-Z]+", text)
    for word in words:
        # 既にある英語辞書から英単語を検索する。
        result = eng2kanaData.get(word)

        if result is None:
            # もしまだない英単語の場合は読み方の取得を行う。
            async with session.get(
                f"https://www.sljfaq.org/cgi/e2k_ja.cgi?word={word.replace(' ', '+')}", headers=HEADERS
            ) as r:
                eng2kanaData[word] = BeautifulSoup(await r.text(), "lxml") \
                    .find(class_='katakana-string').string.replace('\n', '')
            result = eng2kanaData[word]

            # 同期しておく。
            loop.create_task(_dumps_eng2kana_data(), name="TTS: Sync eng2kana data")

        text = text.replace(word, result)

    return text


@executor_function
def aiog2p(*args, **kwargs):
    "`run_in_executor_function`を使って非同期に実行できるようにした`pyopenjtalk.g2p`です。"
    return g2p(*args, **kwargs)


NO_JOINED_TWICE_CHARS = (
    "ー", "、", "。", "っ", "ゃ", "ゅ", "ょ",
    "ッ", "ャ", "ュ", "ョ"
)
REPLACES = (
    ("（", "("), ("）", ")"), ("＜", ""), ("＞", ""), ("？", "?")
)
async def adjust_text(text: str, gtts: bool = False) -> str:
    "日本語の文章をちょうどよく調整します。"
    if len(text) > 40:
        text = text[:41] + " いかしょうりゃく"

    for before, after in REPLACES:
        text = text.replace(before, after)
    # 二回連続の「っ」などを一つにする。
    for char in NO_JOINED_TWICE_CHARS:
        text = sub(f"{char}+", char, text)
    # 連続するwは一つにする。にする。
    text = sub("w{2,}", "わらわら", text)
    # 日本語の一部文字列を最適な文字列にする。
    text = text.replace("()", "かっこしっしょう") \
        .replace("(笑)", "かっこわらい").replace("(", "かっこ、") \
        .replace(")", "、かっことじ")

    if not gtts:
        # 読めない文字は消す。
        text = await aiog2p(text, kana=True)
        text = "".join(char for char in text if char in ALLOWED_CHARACTERS)

    # 英語をかなにする。
    return await eng2kana(text)


class Agent:
    "音声合成の音声のクラスです。"

    def __init__(
        self, type_: VoiceTypes, name: str, agent: str,
        details: str, emoji: Optional[str] = None
    ):
        self.type, self.name, self.agent, self.details = type_, name, agent, details
        self.emoji = emoji

    async def synthe(self, text: str, path: str) -> Optional[Source]:
        "音声合成を行います。"
        text = await adjust_text(text)
        if text:
            return await globals()[self.type.name](text, path, self.agent)

    @property
    def code(self) -> str:
        return f"{self.type.name}-{self.agent}"

    @staticmethod
    def from_agent_code(code: str) -> Agent:
        "`<<VoiceTypes>.name>-<Agent.agent>`の形式のコードからAgentを取得します。"
        return AGENTS[code]


with open(AGENTS_JSON, "r",encoding="utf8") as f:
    for type_, datas in load(f).items():
        for agent, data in datas.items():
            AGENTS[f"{type_}-{agent}"] = Agent(
                getattr(VoiceTypes, type_), data["name"], agent, data["details"],
                data.get("emoji")
            )


class SyntheError(Exception):
    "音声合成失敗時に発生するエラーです。"


@executor_function
def _synthe(log_name: str, commands: str, text: str):
    # 音声合成のコマンドを実行します。
    proc = Popen(commands, stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)
    try:
        _, stderr_ = proc.communicate(bytes(text, encoding="utf-8"), 5)
    except TimeoutExpired:
        proc.kill()
        raise SyntheError(f"{log_name}: 音声合成に失敗しました。ERR:TimeoutExpired")
    else:
        if stderr_:
            raise SyntheError(f"{log_name}: 音声合成に失敗しました。ERR:{stderr_}")


def prepare_source(path: str, volume: float = 5.5) -> Source:
    "Sourceを作ります。"
    return discord.PCMVolumeTransformer(discord.FFmpegPCMAudio(
        path, options=f'-filter:a "volume={volume}"'
    )) if discord.opus.is_loaded() else discord.FFmpegOpusAudio(
        path, options=f'-filter:a "volume={volume}"'
    )


#   AquesTalk
AQUESTALK_REPLACE_CHARACTERS = {
    "ぁ": "あ", "ぃ": "い", "ぅ": "う", "ぇ": "え", "ぉ": "お",
    "ァ": "あ", "ィ": "い", "ゥ": "う", "ェ": "え", "ォ": "お"
}
"AquesTalkで読めない文字の置き換えに使う辞書"
async def aquestalk(text: str, path: str, agent: Union[Literal["f1", "f2"], str]) -> Source:
    "AquesTalkで音声合成をします。"
    # AquesTalk用に文字列を調整する。
    for char in AQUESTALK_REPLACE_CHARACTERS:
        text = text.replace(char, AQUESTALK_REPLACE_CHARACTERS[char])

    # 一番最初に存在しているNO_JOINED_TWICE_CHARSの文字を消す。
    new_text, first = "", True
    for char in text:
        if char in NO_JOINED_TWICE_CHARS:
            if first:
                continue
        elif first:
            first = False
        new_text += char

    # 音声合成をする。
    await _synthe(
        f"AquesTalk[{agent}]", f"./{f'{AQUESTALK_DIRECTORY}/{agent}'} 130 > {path}", text
    )

    return prepare_source(path, 2.2)


#   OpenJTalk
async def openjtalk(text: str, path: str, agent:str) -> Source:
    "OpenJTalkで音声合成を行います。"
    await _synthe(
        f"OpenJTalk[{agent}]", f"""{OPENJTALK} -x {OPENJTALK_DICTIONARY}
            -m {f'{OPENJTALK_VOICE_DIRECTORY}/{agent}.htsvoice'} -r 1.0 -ow {path}"""
                .replace("\n", ""), text
    )
    return prepare_source(path)


#   gTTS
@executor_function
def _gtts(text: str, path: str, agent:str):
    gTTS(text, lang=agent).save(path)


async def gtts(text: str, path: str, agent:str) -> Source:
    "gTTSを使用して音声合成をします。"
    await _gtts(text, path, agent)
    return prepare_source(path)