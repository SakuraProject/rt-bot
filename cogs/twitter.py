# Free RT - Twitter

from __future__ import annotations

from typing import TYPE_CHECKING, Union

from collections import defaultdict
from asyncio import Event
from os.path import exists

from discord.ext import commands
import discord

from tweepy import API, OAuth1UserHandler
from tweepy.asynchronous import AsyncStream
from tweepy.models import Status
from tweepy.errors import NotFound, Forbidden

from jishaku.functools import executor_function
from aiofiles import open as aioopen
from ujson import load, dumps

if TYPE_CHECKING:
    from asyncio import AbstractEventLoop
    from aiomysql import Pool
    from util import Backend


class DataManager:

    TABLE = "TwitterNotification"
    DEFAULT_MAX = 5

    def __init__(self, loop: "AbstractEventLoop", pool: "Pool"):
        self.pool = pool
        loop.create_task(self._prepare_table())

    async def _prepare_table(self):
        # テーブルを準備します。
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"""CREATE TABLE IF NOT EXISTS {self.TABLE} (
                        GuildID BIGINT, ChannelID BIGINT, UserName TEXT
                    );"""
                )
                await self._update_users(cursor)
        self.ready.set()

    async def _read(self, cursor, channel, username):
        await cursor.execute(
            f"SELECT * FROM {self.TABLE} WHERE ChannelID = %s AND UserName = %s;",
            (channel.id, username)
        )
        return await cursor.fetchone()

    async def write(self, channel: discord.TextChannel, username: str) -> None:
        "設定を保存します。"
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                assert not await self._read(cursor, channel, username), "既に設定されています。"
                await cursor.execute(
                    f"SELECT * FROM {self.TABLE} WHERE GuildID = %s;",
                    (channel.guild.id,)
                )
                assert len(await cursor.fetchall()) <= self.DEFAULT_MAX, "追加しすぎです。"
                await cursor.execute(
                    f"INSERT INTO {self.TABLE} VALUES (%s, %s, %s);",
                    (channel.guild.id, channel.id, username)
                )

    async def delete(self, channel: discord.TextChannel, username: str) -> None:
        "設定を削除します。"
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                assert await self._read(cursor, channel, username), "その設定はありません。"
                await cursor.execute(
                    f"DELETE FROM {self.TABLE} WHERE ChannelID = %s AND UserName = %s;",
                    (channel.id, username)
                )

    async def _update_users(self, cursor):
        self.users = defaultdict(list)
        await cursor.execute(
            f"SELECT ChannelID, UserName FROM {self.TABLE};"
        )
        for channel_id, username in await cursor.fetchall():
            self.users[username].append(channel_id)

    async def update_users(self) -> list[tuple[int, str]]:
        "設定のキャッシュを更新します。"
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await self._update_users(cursor)


class TwitterNotification(commands.Cog, DataManager, AsyncStream):

    TWITTERID_HEADERS = {
        "authority": "tweeterid.com",
        "sec-ch-ua": "^\\^Microsoft",
        "accept": "*/*",
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "x-requested-with": "XMLHttpRequest",
        "sec-ch-ua-mobile": "?0",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36 Edg/93.0.961.38",
        "sec-ch-ua-platform": "^\\^Windows^\\^",
        "origin": "https://tweeterid.com",
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
        "referer": "https://tweeterid.com/",
        "accept-language": "ja,en;q=0.9,en-GB;q=0.8,en-US;q=0.7",
    }
    BASE_URL = "https://twitter.com/{}/status/{}"
    users: defaultdict[str, list[int]]

    def __init__(self, bot: "Backend"):
        self.bot = bot
        self.ready = Event()

        self.user_cache = {}
        if exists("data/twitter.json"):
            with open("data/twitter.json", "r") as f:
                self.user_cache = load(f)
        else:
            with open("data/twitter.json", "w") as f:
                f.write(r"{}")

        if "twitter" in self.bot.secret:
            oauth = OAuth1UserHandler(
                self.bot.secret["twitter"]["consumer_key"],
                self.bot.secret["twitter"]["consumer_secret"]
            )
            oauth.set_access_token(
                self.bot.secret["twitter"]["access_token"],
                self.bot.secret["twitter"]["access_token_secret"]
            )
            self.api = API(oauth)

            super(commands.Cog, self).__init__(self.bot.loop, self.bot.mysql.pool)
            super(DataManager, self).__init__(**self.bot.secret["twitter"])

            self.connected = False
            self.cache: dict[str, str] = {}
            self.main_task = self.bot.loop.create_task(self.start_stream())

    def filter(self, *args, **kwargs):
        # connectedを使えるようにするためにオーバーライドした関数です。
        self.connected = True
        super().filter(*args, **kwargs)

    def disconnect(self, *args, **kwargs):
        # connectedを使えるようにするためにオーバーライドした関数です。
        self.connected = False
        super().disconnect(*args, **kwargs)

    def get_url(self, status: Union[Status, tuple[str, int]]) -> str:
        "渡されたStatusからツイートのURLを取得します。"
        return self.BASE_URL.format(
            status.user.screen_name, status.id_str
        ) if isinstance(status, Status) else self.BASE_URL.format(*status)

    async def on_status(self, status: "Status"):
        # ツイートを取得した際に呼ばれる関数です。
        if status.user.screen_name not in self.users:
            return
        for channel_id in self.users[status.user.screen_name]:
            # 通知対象のユーザーのツイートなら通知を行います。
            if not (channel := self.bot.get_channel(channel_id)):
                # もし通知するチャンネルが見当たらない場合はその設定を削除する。
                try:
                    self.users[status.user.screen_name].remove(channel_id)
                    return await self.delete(
                        discord.Object(channel_id),
                        status.user.screen_name
                    )
                except AssertionError:
                    ...

            # Tweetに飛ぶリンクボタンを追加しておく。
            view = discord.ui.View(timeout=1)
            view.add_item(discord.ui.Button(
                label="Tweetを見る", url=self.get_url(status)
            ))
            # メッセージを調整する。
            if hasattr(status, "retweeted_status") and status.retweeted_status:
                # リツイート
                status.text = status.text.replace(
                    "RT @", "🔁 Retweeted @", 1
                )
            elif hasattr(status, "quoted_status") and status.quoted_status:
                # 引用リツイート
                status.text = "🔁 Retweeted [Original]({})\n{}".format(
                    self.get_url(status.quoted_status), status.text
                )
            elif (hasattr(status, "in_reply_to_status_id")
                    and status.in_reply_to_status_id):
                # 返信
                status.text = "⤴ Replied [Original]({})\n{}".format(
                    self.get_url((
                        status.in_reply_to_screen_name,
                        status.in_reply_to_status_id
                    )), status.text
                )
            # メンションが飛ばないように@は全角に置き換えておく。
            status.text = status.text.replace("@", "＠")

            try:
                # 通知の送信を行う。
                await channel.webhook_send(
                    content=status.text,
                    username=status.user.screen_name +
                    ("✅" if status.user.verified else "")
                    + " - RT Twitter Notification",
                    avatar_url=(
                        "" if status.user.default_profile_image
                        else status.user.profile_image_url_https), view=view)
            except discord.Forbidden:
                await channel.send(
                    "Twitter通知をしようとしましたが権限がないため通知に失敗しました。\n"
                    "チャンネルのWebhookを管理できるように権限を付与してください。\n"
                    "またRTにはたくさんの機能があり全てを動かすのなら管理者権限を付与する方が手っ取り早いです。"
                )
            except Exception as e:
                await channel.send(
                    f"Twitter通知をしようとしましたが失敗しました。\nエラーコード：`{e}`"
                )

    async def write_user_cache(self):
        async with aioopen("data/twitter.json", "w") as f:
            await f.write(dumps(self.user_cache))

    @executor_function
    def _get_user_id(self, username: str) -> tuple[str, bool]:
        write = False
        if username not in self.user_cache:
            # キャッシュに既にあるのならそれを使う。
            self.user_cache[username] = self.api.get_user(screen_name=username).id_str
            write = True
        return self.user_cache[username], write

    async def get_user_id(self, username: str) -> str:
        "ユーザー名からユーザーのIDを取得する関数です。"
        if (data := await self._get_user_id(username))[1]:
            await self.write_user_cache()
        return data[0]

    async def start_stream(self, disconnect: bool = False) -> None:
        "Twitterのストリームを開始します。"
        if disconnect and self.connected:
            self.disconnect()
        if hasattr(self, "ready"):
            await self.ready.wait()
            del self.ready
        if self.users:
            follow = []
            for username in list(self.users.keys()):
                try:
                    follow.append(await self.get_user_id(username))
                except Exception as e:
                    for channel_id in self.users[username]:
                        if channel := self.bot.get_channel(channel_id):
                            self.users[username].remove(channel_id)
                            if isinstance(e, Forbidden) and "suspen" in str(e):
                                await channel.send(
                                    "Twitter通知を試みましたが、ユーザーが凍結か何か起きているため通知できませんでした。"
                                )
                            elif isinstance(e, NotFound):
                                await channel.send(
                                    "Twitter通知を試みましたが、ユーザーが見つからないため通知できませんでした。"
                                )
                            else:
                                await channel.send(
                                    f"Twitter通知を試みましたが、何らかのエラーにより失敗しました。\nCode: `{e}`"
                                )
                                continue
                        await self.delete(discord.Object(channel_id), username)
            self.filter(follow=follow)

    def cog_unload(self):
        if self.connected:
            self.disconnect()
            self.main_task.cancel()

    @commands.group(
        aliases=["ツイッター", "tw"], extras={
            "headding": {"ja": "Twitter通知", "en": "Twitter Notification"},
            "parent": "ServerUseful"
        }
    )
    async def twitter(self, ctx):
        """!lang ja
        --------
        Twitterの指定したユーザーのツイートを指定したチャンネルに通知させます。

        Aliases
        -------
        tw, ツイッター

        !lang en
        --------
        Notify the specified channel of tweets from the specified user on Twitter.

        Aliases
        -------
        tw"""
        if not ctx.invoked_subcommand:
            await ctx.reply("使用方法が違います。 / It is used in different ways.")

    @twitter.command("set", aliases=["s", "設定"])
    @commands.has_permissions(manage_channels=True, manage_webhooks=True)
    @commands.cooldown(1, 60, commands.BucketType.channel)
    async def set_(self, ctx, onoff: bool, *, username):
        """!lang ja
        --------
        Twitterの通知を設定します。  
        このコマンドを実行したチャンネルに指定したユーザーのツイートの通知が来るようになります。

        Parameters
        ----------
        onoff : bool
            onまたはoffで通知を有効にするか無効にするかです。
        username : str
            通知する対象のユーザーの名前です。  
            `@`から始まるものです。

        Examples
        --------
        `rf!twitter set on tasuren1`
        RTの開発者のtasurenのTwitterの通知を有効にします。

        Aliases
        -------
        s, 設定

        !lang en
        --------
        Sets up Twitter notifications.  
        The channel where this command is executed will receive notifications of tweets from the specified user.

        Parameters
        ----------
        onoff : bool
            Enables or disables notifications with on or off.
        username : str
            The name of the user to be notified.  
            It must start with `@`.

        Examples
        --------
        `rf!twitter set on tasuren1`
        Enables Twitter notifications for the RT developer tasuren.

        Aliases
        -------
        s"""
        await ctx.trigger_typing()
        try:
            if username in self.user_cache:
                del self.user_cache[username]
            if onoff:
                await self.get_user_id(username)
                await self.write(ctx.channel, username)
            else:
                await self.delete(ctx.channel, username)
                await self.write_user_cache()
        except AssertionError:
            await ctx.reply(
                {"ja": "既に設定されています。\nまたは設定しすぎです。",
                 "en": "The username is already set.\nOr it is set too high."}
                if onoff else {
                    "ja": "設定されていません。",
                    "en": "The username is not set yet."
                }
            )
        except NotFound:
            await ctx.reply(
                {"ja": "そのユーザーが見つかりませんでした。",
                 "en": "The user is not found."}
            )
        else:
            self.bot.loop.create_task(self.restart())
            await ctx.reply("Ok")

    async def restart(self):
        await self.update_users()
        await self.start_stream(True)

    @twitter.command("list", aliases=["l", "一覧"])
    async def list_(self, ctx):
        """!lang ja
        --------
        設定しているTwitter通知のリストを表示します。

        Aliases
        -------
        l, 一覧

        !lang en
        --------
        Displays twitter notification settings

        Aliases
        -------
        l"""
        await ctx.reply(
            embed=discord.Embed(
                title="Twitter",
                description="\n".join(
                    "\n".join(
                        f"<#{channel_id}>：{username}"
                        for channel_id in channels
                        if ctx.guild.get_channel(channel_id) is not None
                    ) for username, channels in list(self.users.items())
                )
            )
        )


async def setup(bot):
    await bot.add_cog(TwitterNotification(bot))
