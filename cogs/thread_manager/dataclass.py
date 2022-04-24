# Free-RT.thread_manager - Data Class

from typing import TYPE_CHECKING, Union, Dict, Optional

import discord

from asyncio import Event, wait_for, TimeoutError
from functools import wraps

from util import Table

from .constants import DB, MAX_CHANNELS

if TYPE_CHECKING:
    from .__init__ import ThreadManager


class ThreadNotification(Table):
    __allocation__ = "GuildID"
    channels: list[tuple[int, int]]


class DataManager:
    def __init__(self, cog: "ThreadManager"):
        self.cog, self.pool = cog, cog.pool
        self.cog.bot.loop.create_task(self.prepare_table())
        self.notification = ThreadNotification(self.cog.bot)

    async def prepare_table(self) -> None:
        """テーブルを準備する。"""
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"""CREATE TABLE IF NOT EXISTS {DB} (
                        GuildID BIGINT, ChannelID BIGINT PRIMARY KEY NOT NULL
                    );"""
                )

    def check_notification_onoff(self, guild_id: int) -> bool:
        return "channels" in self.notification[guild_id]

    async def process_notification(self, thread: discord.Thread, mode: str) -> None:
        if self.check_notification_onoff(thread.guild.id):
            for tentative in self.notification[thread.guild.id].channels:
                if tentative[0] == thread.parent_id:
                    await thread.send(f"<@&{tentative[1]}>, {mode}")
                    break

    def get_data(self, guild_id: int) -> "GuildData":
        """サーバーのデータクラスを取得します。"""
        return GuildData(self.cog, guild_id)


def wait_ready(coro):
    # データベースの準備ができるまで待つ。
    @wraps(coro)
    async def new_coro(self: "GuildData", *args, **kwargs):
        try:
            await wait_for(self.lock.wait(), 6, loop=self.cog.bot.loop)
        except TimeoutError:
            raise TimeoutError("データベースに嫌われてしまいました。悲しいです。")
        else:
            return await coro(self, *args, **kwargs)
    return new_coro


class GuildData:
    def __init__(self, cog: "ThreadManager", guild: Union[int, discord.Guild]):
        self.cog, self.pool = cog, cog.pool
        self.lock: Event = Event(loop=cog.bot.loop)
        self.cog.bot.loop.create_task(self.update_data())
        self.guild: discord.Guild = self.cog.bot.get_guild(guild) \
            if isinstance(guild, int) else guild

        self.channels: Dict[int, discord.TextChannel] = {}

    async def update_data(self) -> None:
        """このクラスにあるセーブデータを新しいものに更新します。
        このクラスをインスタンス化した際に自動でこの関数は実行されます。"""
        if self.lock.is_set():
            self.lock.clear()
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"SELECT * FROM {DB} WHERE GuildID = %s;",
                    (self.guild.id,)
                )
                for row in await cursor.fetchall():
                    if row:
                        self.channels[row[1]] = self.guild.get_channel(row[1])
        self.lock.set()

    @wait_ready
    async def get_channels(self) -> Dict[int, discord.TextChannel]:
        """監視対象チャンネルの一覧を取得します。
        データ読み込みが完了するまで待ってから`channels`を返します。"""
        return self.channels

    @wait_ready
    async def add_channel(self, channel_id: int) -> None:
        """監視チャンネルリストに追加する。"""
        assert len(self.channels) < MAX_CHANNELS, "これ以上追加できません。"
        self.channels[channel_id] = self.guild.get_channel(channel_id)
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"""INSERT IGNORE INTO
                        {DB} (GuildID, ChannelID)
                    VALUES (%s, %s);""",
                    (self.guild.id, channel_id)
                )

    @wait_ready
    async def remove_channel(self, channel_id: int) -> None:
        """監視チャンネルリストからチャンネルを削除する。"""
        del self.channels[channel_id]
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"""DELETE FROM {DB}
                    WHERE GuildID = %s AND ChannelID = %s;""",
                    (self.guild.id, channel_id)
                )