# RT TTS - Manager

from __future__ import annotations

from typing import TYPE_CHECKING, Optional, Any

from asyncio import Task

import discord

from .voice import Voice

if TYPE_CHECKING:
    from .__init__ import TTSCog


EMOJI_ERROR = "<:error:878914351338246165>"


async def try_add_reaction(message: discord.Message, emoji: str):
    "ただリアクション付与をtryするだけ。"
    try: await message.add_reaction(emoji)
    except Exception: ...


class ExtendedVoice(Voice):
    "サーバー辞書にある文字列を交換するように拡張したVoiceです。"

    def adjust_text(self, text: str) -> str:
        if "dictionary" in self.cog.guild[self.message.guild.id]:
            for key, value in list(self.cog.guild[self.message.guild.id].dictionary.items()):
                text = text.replace(key, value)
        return text


class Manager:
    "読み上げを管理するためのクラスです。"

    def __init__(self, cog: TTSCog, guild: discord.Guild):
        self.cog, self.guild = cog, guild
        self.vc: discord.VoiceClient = guild.voice_client
        self.queues: list[Voice] = []
        self.channels: list[int] = []
        self._closing = False

    def add_channel(self, channel_id: int) -> None:
        "読み上げチャンネルを追加します。"
        assert len(self.channels) < 10, {
            "ja": "これ以上チャンネルを追加できません。", "en": "You can't add a channel more than 10."
        }
        self.channels.append(channel_id)

    def remove_channel(self, channel_id: int) -> bool:
        "読み上げ対称チャンネルを削除します。"
        if channel_id in self.channels:
            self.channels.remove(channel_id)
            return True
        return False

    def check_channel(self, channel_id: int) -> None:
        "読み上げ対称チャンネル可動かをチェックします。"
        return channel_id in self.channels

    def print(self, *args, **kwargs) -> None:
        "デバッグ用のprint"
        self.cog.bot.print(f"[{self}]", *args, **kwargs)

    async def disconnect(self, reason: Optional[Any] = None, force: bool = False) -> None:
        "切断をします。これをやったあとキューのお片付けをしたい場合はdelしてください。"
        self._closing = True
        try:
            await self.vc.disconnect(force=force)
            if reason is not None:
                await self.guild.get_channel(self.channels[0]).send(reason)
        except Exception: ...

    async def add(self, message: discord.Message):
        "渡されたメッセージを読み上げキューに追加します。"
        queue = ExtendedVoice(self, message)
        try:
            await queue.synthe()
        except Exception as e:
            if self.cog.bot.test:
                await try_add_reaction(message, EMOJI_ERROR)
            self.print("Failed to do voice synthesis:", f"{e.__class__.__name__} - {e}")
        else:
            self.queues.append(queue)
            try: self.queues[1]
            except IndexError: self.play()

    async def _after(self, e: Optional[Exception]):
        if self.queues:
            if e:
                self.print("Failed to play voice:", f"{e.__class__.__name__} - {e}")
                self.cog.bot.loop.create_task(
                    try_add_reaction(self.queues[0].message, EMOJI_ERROR),
                    name=f"{self}: Try add error reaction"
                )

            await self.queues[0].close()
            del self.queues[0]
            self.play()

    def play(self):
        if self.queues:
            self.print("Play voice:", self.queues[0])
            if self.queues[0].source is None:
                # 普通ないがもしsourceが用意されていないのなら再生をしない。
                self.cog.bot.loop.create_task(
                    self._after(None), name=f"{self}: After playing voice"
                )
            elif self.vc.is_connected():
                self.vc.play(
                    self.queues[0].source, after=lambda e: self.cog.bot.loop.create_task(
                        self._after(e), name=f"{self}: After playing voice"
                    )
                )

    def clean(self, voice: Voice) -> Task:
        "渡されたVoiceのお片付けをします。第二引数にもし数字を渡した場合はキューを消した後にplayを実行します。"
        return self.cog.bot.loop.create_task(
            voice.close(), name=f"{self}: Remove voice cache file"
        )

    def __del__(self):
        for queue in self.queues:
            self.clean(queue)

    def __str__(self):
        return f"<Manager guild={repr(self.guild)} >"