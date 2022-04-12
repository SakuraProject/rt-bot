# RT - Captcha

from typing import TypedDict, Optional, Dict, Tuple

from discord.ext import commands, tasks
import discord

from rtutil import DatabaseManager as RUDatabaseManager
from rtlib import RT, DatabaseManager, websocket

from aiomysql import Pool, Cursor
from ujson import loads, dumps
from time import time

from .image_captcha import ImageCaptcha
from .word_captcha import WordCaptcha
from .web_captcha import WebCaptcha


class TimeoutDataManager(RUDatabaseManager):

    TABLE = "captchaTimeout"

    def __init__(self, cog: "Captcha"):
        self.pool: Pool = cog.bot.mysql.pool
        self.cog = cog
        self.cog.bot.loop.create_task(self.init_timeout_table())

    async def init_timeout_table(self, cursor: Cursor = None) -> None:
        "データベースにテーブルを作る関数でクラスのインスタンス化時に自動で実行されます。"
        await cursor.execute(
            f"""CREATE TABLE IF NOT EXISTS {self.TABLE} (
                GuildID BIGINT PRIMARY KEY NOT NULL, Timeout INT, Kick TINYINT
            );"""
        )

    async def save_timeout(
        self, guild_id: int, timeout: int = 60, kick: bool = False, cursor: Cursor = None
    ) -> None:
        assert 1 <= timeout <= 180, "タイムアウトの範囲が広すぎます。"
        await cursor.execute(
            f"""INSERT INTO {self.TABLE} VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE Timeout = %s, Kick = %s;""",
            (guild_id, timeout, int(kick), timeout, int(kick))
        )

    async def read_timeout(self, cursor, guild_id: int) -> Optional[Tuple[int, bool]]:
        await cursor.execute(
            f"SELECT Timeout, Kick FROM {self.TABLE} WHERE GuildID = %s;",
            (guild_id,)
        )
        if (row := await cursor.fetchone()):
            return (row[0], bool(row[1]))

    async def process_cache(self, now: float, cursor: Cursor = None) -> None:
        "コグにあるキャッシュでタイムアウトしているものを削除します。"
        for captcha in list(self.cog.captchas.values()):
            for key in list(captcha.queue.keys()):
                id_ = int(key[:(i:=key.find("-"))])
                obj = self.cog.bot.get_channel(id_)
                if obj is None:
                    obj = self.cog.bot.get_guild(id_)
                if isinstance(obj, discord.Guild):
                    obj = obj
                else:
                    obj = obj.guild
                row = await self.read_timeout(cursor, obj.id)
                timeout, kick = row or (60, False)
                user = discord.Object(int(key[i+1:]))
                if now - captcha.queue[key][1] > (timeout := 60 * timeout):
                    del captcha.queue[key]
                    if kick:
                        try:
                            await obj.kick(
                                user, reason="認証のタイムアウトのため。"
                            )
                        except Exception as e:
                            print(self.cog.__cog_name__, "Passed remove cache:", obj, key, e)
                if ((key := f"{obj.id}-{user.id}") in self.cache
                        and now - self.cache[key] > timeout):
                    del self.cache[key]


class DataManager(DatabaseManager):
    def __init__(self, db):
        self.db = db

    async def init_table(self, cursor):
        await cursor.create_table(
            "captcha", {
                "GuildID": "BIGINT",
                "ChannelID": "BIGINT",
                "Mode": "TEXT",
                "RoleID": "BIGINT",
                "Extras": "TEXT"
            }
        )

    async def save(
        self, cursor, channel: discord.TextChannel,
        mode: str, role_id: int, extras: dict
    ) -> None:
        target = {"GuildID": channel.guild.id}
        change = {
            "ChannelID": channel.id, "Mode": mode,
            "RoleID": role_id, "Extras": extras
        }
        if await cursor.exists("captcha", target):
            await cursor.update_data("captcha", change, target)
        else:
            target.update(change)
            await cursor.insert_data("captcha", target)

    async def delete(self, cursor, channel: discord.TextChannel) -> None:
        target = {"GuildID": channel.guild.id, "ChannelID": channel.id}
        if await cursor.exists("captcha", target):
            await cursor.delete("captcha", target)

    async def load(self, cursor, guild_id: int) -> tuple:
        target = {"GuildID": guild_id}
        if await cursor.exists("captcha", target):
            if (row := await cursor.get_data("captcha", target)):
                return row
        return ()


class Captchas(TypedDict):
    image: ImageCaptcha
    word: WordCaptcha
    web: WebCaptcha


class ClickCaptchaView(discord.ui.View):
    def __init__(self, bot_id: int, *args, **kwargs):
        self.bot_id = bot_id
        kwargs["timeout"] = kwargs.get("timeout", None)
        super().__init__(*args, **kwargs)

    @discord.ui.button(
        label="認証",  custom_id="ClickCaptchaButton",
        style=discord.ButtonStyle.primary, emoji="🔎",
    )
    async def captcha(self, _, interaction: discord.Interaction):
        if interaction.message.author.id == self.bot_id:
            role = interaction.guild.get_role(
                int(interaction.message.content)
            )
            content = ""
            if role:
                if interaction.user.get_role(role.id) is None:
                    try:
                        await interaction.user.add_roles(role)
                    except discord.Forbidden:
                        content = "権限がないのでロールを付与できませんでした。"
                    except discord.HTTPException as e:
                        content = f"何かエラーが発生してロールを付与できませんでした。\ncode:{e}"
                    else:
                        content = "ロールを付与しました。"
            else:
                content = "付与するロールが見つからなかったので認証に失敗しました。"
            if content:
                try:
                    await interaction.response.send_message(
                        content=content, ephemeral=True
                    )
                except discord.NotFound:
                    pass


class OldCaptcha(commands.Cog, DataManager, TimeoutDataManager):
    def __init__(self, bot: RT):
        self.bot = bot
        self.view = ClickCaptchaView(self.bot.user.id)
        self.bot.add_view(self.view)
        self.captchas: Captchas = {
            "image": ImageCaptcha(self),
            "word": WordCaptcha(self),
            "web": WebCaptcha(
                self, (
                    self.bot.secret["test_hCaptcha"]
                    if bot.test else
                    self.bot.secret["hCaptcha"]
                )
            )
        }
        self.sitekey = (
            "20000000-ffff-ffff-ffff-000000000002"
            if bot.test else
            "0a50268d-fa1e-405f-9029-710309aad1b0"
        )
        self.queue_killer.start()
        self.cache: Dict[str, float] = {}
        self.bot.loop.create_task(self.init_database())
        super(DataManager, self).__init__(self)

    async def get_timeout(self, guild_id: int) -> int:
        if (row := await self.read_timeout(guild_id)):
            return row[0]
        return 60

    @commands.command(
        extras={
            "headding": {
                "ja": "RTの古い認証機能です。",
                "en": "RT's old captcha feature."
            },
            "parent": "Other"
        }
    )
    @commands.has_permissions(administrator=True)
    @commands.cooldown(1, 10, commands.BucketType.guild)
    async def old_captcha(self, ctx, mode, *, role: discord.Role = None):
        """!lang ja
        --------
        古い認証機能です。  
        新しい`rt!captcha`を使用してください。  
        もしこの機能を使っていて無効にしたい場合は`rt!old_captcha off`と実行してください。

        !lang en
        --------
        This is an old authentication feature.  
        Please use the newer `rt!captcha`.  
        If you are using this feature and want to disable it, use `rt!old_captcha off`."""
        if role is None:
            await self.delete(ctx.channel)
        elif mode == "click":
            return await ctx.send(
                str(role.id), embed=discord.Embed(
                    title="ワンクリック認証",
                    description="下のボタンをクリックすることで認証できます。",
                    color=self.bot.colors["normal"]
                ), view=self.view
            )
        else:
            extras = ""
            if mode not in self.captchas:
                extras = mode
                mode = "word"
            await self.save(ctx.channel, mode, role.id, extras)
        await ctx.reply("Ok")

    @commands.command()
    async def ct(self, ctx: commands.Context, timeout: int, kick: bool):
        try:
            await self.save_timeout(ctx.guild.id, timeout, kick)
        except AssertionError:
            await ctx.reply(
                {"ja": "タイムアウトは一分から三時間までの範囲である必要があります。",
                 "en": "The timeout should be in the range of one minute to three hours."}
            )
        else:
            await ctx.reply("Ok")

    async def init_database(self):
        super(commands.Cog, self).__init__(
            self.bot.mysql
        )
        await self.init_table()

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member):
        if (not self.bot.is_ready() or member.bot
                or (key := f"{member.guild.id}-{member.id}") in self.cache):
            # 準備中,Botまたは既に認証を送信したのなら何もしない。
            return

        row = await self.load(member.guild.id)
        if len(row) >= 4:
            captcha = self.captchas[row[2]]
            channel = discord.utils.get(member.guild.text_channels, id=row[1])
            if channel:
                await captcha.captcha(channel, member)
            self.cache[key] = time()

    def cog_unload(self):
        self.queue_killer.cancel()

    @tasks.loop(seconds=30)
    async def queue_killer(self):
        # 放置されて溜まってしまっている認証queueを削除する。
        now = time()
        await self.process_cache(now)

    def remove_cache(self, member: discord.Member) -> None:
        del self.cache[f"{member.guild.id}-{member.id}"]

    @websocket.websocket("/api/captcha")
    async def websocket_(self, ws: websocket.WebSocket, _):
        self.websocket_.ws.print("I'm ready to captcha")
        await ws.send("on_ready")

    @websocket_.event("on_success")
    async def on_seccess(self, ws: websocket.WebSocket, user_id: str):
        self.websocket_.ws.print(f"On success: {user_id}")
        for key, (_, _, channel) in list(self.captchas["web"].queue.items()):
            if key.endswith(user_id):
                self.websocket_.ws.print(f"Adding role to {user_id}...")
                await self.captchas["web"].success_user(
                    {
                        "user_id": int(user_id), "guild_id": int(key[:key.find("-")]),
                        "channel": channel
                    }
                )
            del self.captchas["web"].queue[key]
        await ws.send("on_ready")


def setup(bot):
    bot.add_cog(OldCaptcha(bot))
