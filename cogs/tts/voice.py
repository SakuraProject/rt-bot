# RT TTS - Voice

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

import discord

from aiofiles.os import remove

from .agents import Source, Agent, prepare_source

if TYPE_CHECKING:
    from .manager import Manager


OUTPUT_DIRECTORY = "cogs/tts/outputs"


class Voice:
    "音声クラスです。再生キューに使うクラスです。"

    path: Optional[str] = None

    def __init__(self, manager: Manager, message: discord.Message):
        self.cog, self.message, self.manager = manager.cog, message, manager
        self.source: Optional[Source] = None

    def print(self, *args, **kwargs):
        self.manager.print(f"[{self}]", *args, **kwargs)

    def adjust_text(self, text: str) -> str:
        """文字列を調整する関数です。
        デフォルトでは何もしません。
        オーバーライドして拡張するためのものです。"""
        return text

    async def synthe(self) -> None:
        """音声合成を行います。Routineの場合はRoutineのSourceを作ります。
        インスタンス変数の`source`にSource入れられます。"""
        # Routineがあるかチェックをする。
        for routine in self.cog.user[self.message.author.id].get("routines", ()):
            if any(key in self.message.content for key in routine["keys"]):
                if self.cog.RTCHAN:
                    ... # TODO: りつたんでもバックエンドを経由してRoutineを手に入れて再生を行う。
                else:
                    # Routineがあればそれの再生を行う。
                    self.source = prepare_source(routine["path"], 1.5)
                    return self.print("Found routine:", routine)

        # Agentコードを取得する。
        code = self.cog.user[self.message.author.id].get("voice")
        if code is None:
            if self.cog.bot.cogs["Language"].get(self.message.author.id) == "ja":
                code = "openjtalk-mei"
            else:
                code = "gtts-en"

        # 音声合成を行う。
        self.path = f"{OUTPUT_DIRECTORY}/{self.message.author.id}-{self.message.id}.wav"
        self.print("Doing voice synthesis...: ", code)
        self.source = await Agent.from_agent_code(code) \
            .synthe(self.adjust_text(self.message.content), self.path)

    async def close(self) -> None:
        "音声合成で作成したファイルを削除します。"
        if self.path is not None:
            self.print("Cleaning...")
            try: await remove(self.path)
            except Exception: ...
            self.path = None

    def is_closed(self) -> bool:
        "お片付けが済んでいるかどうかです。"
        return self.path is None

    def __del__(self):
        if not self.is_closed(): self.cog.bot.loop.create_task(
            self.close(), name=f"{self}: Closing..."
        )

    def __str__(self) -> str: 
        return f"<Voice author={self.message.author} path={self.path}>"