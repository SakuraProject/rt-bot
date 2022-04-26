# Free RT - Global Chat

from typing import TYPE_CHECKING

from discord.ext import commands
import discord

from collections import defaultdict
from util.mysql_manager import DatabaseManager
from functools import wraps
from time import time

if TYPE_CHECKING:
    from util import Backend


class DataManager(DatabaseManager):
    def __init__(self, db):
        self.db = db

    async def init_table(self, cursor) -> None:
        await cursor.create_table(
            "globalChat", {
                "Name": "TEXT", "ChannelID": "BIGINT",
                "Extras": "JSON"
            }
        )

    async def load_globalchat_name(self, cursor, channel_id: int) -> list:
        target = {"ChannelID": channel_id}
        if await cursor.exists("globalChat", target):
            return await cursor.get_data("globalChat", target)
        else:
            return ()

    async def load_globalchat_channels(self, cursor, name: str) -> list:
        target = {"Name": name}
        if await cursor.exists("globalChat", target):
            return [
                data
                async for data in cursor.get_datas(
                    "globalChat", target
                )
            ]
        else:
            return []

    async def make_globalchat(self, cursor, name: str, channel_id: int, extras: dict) -> None:
        target = {"Name": name, "ChannelID": channel_id, "Extras": extras}
        if await cursor.exists("globalChat", {"Name": name}):
            raise ValueError("既に追加されています。")
        else:
            await cursor.insert_data("globalChat", target)

    async def connect_globalchat(self, cursor, name: str, channel_id: int, extras: dict) -> None:
        target = {"Name": name, "ChannelID": channel_id}
        if await cursor.exists("globalChat", target):
            raise ValueError("既に接続しています。")
        else:
            target["Extras"] = extras
            await cursor.insert_data("globalChat", target)

    async def disconnect_globalchat(self, cursor, name: str, channel_id: int) -> None:
        target = {"Name": name, "ChannelID": channel_id}
        if await cursor.exists("globalChat", target):
            await cursor.delete("globalChat", target)
        else:
            raise ValueError(
                "そのグローバルチャットは存在していないまたはチャンネルは接続していません。"
            )

    async def exists_globalchat(self, cursor, name: str) -> bool:
        return await cursor.exists("globalChat", {"Name": name})

    async def update_extras(self, cursor, name: str, extras: dict) -> None:
        target = {"Name": name}
        change = {"Extras": extras}
        if await cursor.exists("globalChat", target):
            await cursor.update("globalChat", change, target)
        else:
            raise ValueError("グローバルチャットが存在しません。")

    async def delete_globalchat(self, cursor, name: str) -> None:
        await cursor.delete("globalChat", {"Name": name})


def require_guild(coro):
    @wraps(coro)
    async def new_coro(self, ctx, *args, **kwargs):
        if ctx.guild:
            return await coro(self, ctx, *args, **kwargs)
        else:
            return await ctx.reply(
                {"ja": "サーバーのみ実行可能です。",
                 "en": "This command can run only server."}
            )
    return new_coro


def require_globalchat(coro):
    @wraps(coro)
    async def new_coro(self, ctx, *args, **kwargs):
        if (row := await self.load_globalchat_name(ctx.channel.id)):
            ctx.row = row
            return await coro(self, ctx, *args, **kwargs)
        else:
            return await ctx.reply(
                {"ja": "このチャンネルはグローバルチャットではありません。",
                 "en": "The channel is not globalchat."}
            )
    return new_coro


class GlobalChat(commands.Cog, DataManager):
    def __init__(self, bot: "Backend"):
        self.bot = bot
        self.blocking = {}
        self.ban_cache = defaultdict(list)
        self.bot.loop.create_task(self.on_ready())

    async def on_ready(self):
        super(commands.Cog, self).__init__(
            self.bot.mysql
        )
        await self.init_table()

    @commands.group(
        aliases=["gc", "ぐろちゃ", "ぐろーばるちゃっと"],
        extras={
            "headding": {
                "ja": "グローバルチャット機能",
                "en": "Global chat."
            }, "parent": "ServerUseful"
        }
    )
    async def globalchat(self, ctx):
        """!lang ja
        --------
        グローバルチャット機能です。  
        いくつかのサーバーのチャンネルをRTを経由してつなげることができます。

        Aliases
        -------
        gc, ぐろちゃ, ぐろーばるちゃっと

        !lang en
        --------
        ..."""
        if not ctx.invoked_subcommand:
            await ctx.reply("使用方法が違います。")

    @globalchat.command()
    @commands.has_permissions(administrator=True)
    @require_guild
    async def make(self, ctx, *, name):
        """!lang ja
        --------
        グローバルチャットを作成します。  
        実行したチャンネルが最初のチャンネルとして設定されます。

        Parameters
        ----------
        name : str
            グローバルチャットの名前です。"""
        try:
            await self.make_globalchat(
                name, ctx.channel.id, {"author": ctx.author.id}
            )
        except ValueError:
            await ctx.reply(
                {"ja": "そのグローバルチャットは既に存在します。",
                 "en": "That name is already used."}
            )
        else:
            await ctx.channel.edit(topic="RT-GlobalChat")
            await ctx.reply(
                {"ja": "グローバルチャットを登録しました。",
                 "en": "Success!"}
            )

    @globalchat.command(name="delete", aliases=["del", "rm"])
    @require_guild
    @require_globalchat
    async def delete_(self, ctx):
        """!lang ja
        --------
        実行したチャンネルに設定されているグローバルチャットを削除(全チャンネルの接続の解除)します。  
        グローバルチャット作成者でないと削除はできません。

        Aliases
        -------
        del, rm

        !lang en
        --------
        ..."""
        if ctx.row[-1]["author"] == ctx.author.id:
            await self.delete_globalchat(ctx.row[0])
            await ctx.channel.edit(topic=None)
            await ctx.reply({"ja": "削除しました。", "en": "Success!"})
        else:
            await ctx.reply(
                {"ja": "グローバルチャットの作成者でなければ削除できません。",
                 "en": "You can't delete the global chat because you are not author."}
            )

    @globalchat.command(aliases=["cong", "コネクト", "接続", "せつぞく"])
    @require_guild
    async def connect(self, ctx, *, name):
        """!lang ja
        --------
        グローバルチャットに接続します。

        Parameters
        ----------
        name : str
            グローバルチャットの名前です。

        Aliases
        -------
        cong, コネクト, 接続, せつぞく

        !lang en
        --------
        Connect to global chat.

        Parameters
        ----------
        name : str
            Global chat name.

        Aliases
        -------
        cong"""
        if await self.exists_globalchat(name):
            if ctx.channel.topic and "RT-GlobalChat" in ctx.channel.topic:
                await ctx.reply("既に接続しています。")
            else:
                rows = await self.load_globalchat_channels(name)
                extras = rows[0][-1]
                try:
                    await ctx.channel.edit(topic="RT-GlobalChat")
                except discord.Forbidden:
                    await ctx.reply("権限がないのでチャンネルの編集に失敗しました。")
                else:
                    await self.connect_globalchat(name, ctx.channel.id, extras)
                    await ctx.reply("Ok")
                    # 入室メッセージを送信する。
                    message = ctx.message
                    message.content = f"{ctx.guild.name}がグローバルチャットに参加しました。"
                    await self.send(message, rows[0])
        else:
            await ctx.reply(
                {"ja": "そのグローバルチャットはありません。",
                 "en": "The global chat is not found."}
            )

    @globalchat.command(aliases=["dis", "leave", "bye", "切断", "せつだん"])
    @require_guild
    async def disconnect(self, ctx):
        """!lang ja
        --------
        グローバルチャットから切断します。  

        Aliases
        -------
        dis, leave, bye, 切断, せつだん

        !lang en
        --------
        Disconnect global chat.

        Aliases
        -------
        dis, leave, bye"""
        if (row := await self.load_globalchat_name(ctx.channel.id)):
            await self.disconnect_globalchat(row[0], ctx.channel.id)
            await ctx.channel.edit(topic=None)
            await ctx.reply(
                {"ja": "グローバルチャットから切断しました。",
                 "en": "I have disconnected to global chat."}
            )
        else:
            await ctx.reply(
                {"ja": "ここはグローバルチャットではないです。",
                 "en": "Here is not the global chat."}
            )

    def similer(self, before: str, after: str) -> bool:
        # 文字列がにた文字列かどうかを調べる。
        m = len(before) if len(before) < 6 else 5
        return any(
            after[i:i + m] in before for i in range(len(after) - m)
        )

    async def send(self, message: discord.Message, row: list) -> None:
        # グローバルチャットにメッセージを送る。
        rows = await self.load_globalchat_channels(row[0])

        # もし返信先があるメッセージなら返信先のEmbedを作っておく。
        if message.author.id in (888057396310716496,):
            return
        embeds = []
        if message.reference:
            if message.reference.cached_message:
                original = message.reference.cached_message
            else:
                ch = self.bot.get_channel(message.channel.id)
                original = (
                    await ch.fetch_message(message.reference.message_id)
                    if ch else None
                )

            embeds.append(
                discord.Embed(
                    description=original.clean_content
                ).set_author(
                    name=original.author,
                    icon_url=getattr(original.author.avatar, "url", "")
                )
            )

        # スタンプがついているのなら添付ファイルにそのスタンプの画像を添付する。
        if message.stickers:
            for sticker in message.stickers:
                embeds.append(
                    discord.Embed(color=message.author.color)
                    .set_image(url=sticker.url)
                    .set_footer(text="添付されたスタンプ")
                )

        # 送る。
        for _, channel_id, _ in rows:
            if message.channel.id == channel_id:
                continue
            else:
                channel = self.bot.get_channel(channel_id)
                if channel:
                    if channel.guild.id not in self.ban_cache:
                        for entry in await channel.guild.bans():
                            self.ban_cache[channel.guild.id].append(
                                entry.user.id
                            )
                    if all(
                        user_id != message.author.id
                        for user_id in self.ban_cache[channel.guild.id]
                    ):
                        try:
                            await channel.webhook_send(
                                username=f"{message.author.name} {message.author.id}",
                                avatar_url=getattr(message.author.avatar, "url", ""),
                                content=message.clean_content, embeds=embeds, files=[
                                    await attachment.to_file()
                                    for attachment in message.attachments
                                ]
                            )
                        except Exception as e:
                            print("Error on global chat :", e)

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if (not message.guild or isinstance(message.channel, discord.Thread)
                or not message.channel.topic or message.author.bot
                or "RT-GlobalChat" not in message.channel.topic):
            return

        row = await self.load_globalchat_name(message.channel.id)
        if row:
            # スパムの場合は一分停止させる。
            if (before := self.blocking.get(message.author.id)):
                if before.get("time", (now := time()) - 1) < now:
                    if self.similer(before["before"], message.clean_content):
                        self.blocking[message.author.id]["count"] += 1
                        if self.blocking[message.author.id]["count"] > 4:
                            self.blocking[message.author.id].update(
                                {"time": now + 60}
                            )
                    elif before["count"] > 4:
                        self.blocking[message.author.id]["count"] = 0
                else:
                    return await message.add_reaction("<:error:878914351338246165>")
            else:
                self.blocking[message.author.id] = {"count": 0}
            self.blocking[message.author.id]["before"] = message.clean_content

            await self.send(message, row)


def setup(bot):
    bot.add_cog(GlobalChat(bot))
