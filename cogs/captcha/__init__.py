# RT - Captcha

from discord.ext import commands, tasks
import discord

from rtlib import DatabaseLocker, mysql, OAuth
from sanic.exceptions import SanicException
from .image_captcha import ImageCaptcha
from .word_captcha import WordCaptcha
from .web_captcha import WebCaptcha
from time import time


class DataManager(DatabaseLocker):
    def __init__(self, db: mysql.MySQLManager):
        self.db: mysql.MySQLManager = db

    async def init_table(self):
        async with self.db.get_cursor() as cursor:
            await cursor.create_table(
                "captcha", {
                    "GuildID": "BIGINT",
                    "ChannelID": "BIGINT",
                    "Mode": "TEXT",
                    "RoleID": "BIGINT",
                    "Extras": "TEXT"
                }
            )

    async def save(self, channel: discord.TextChannel, mode: str,
                   role_id: int, extras: dict) -> None:
        async with self.db.get_cursor() as cursor:
            target = {"GuildID": channel.guild.id}
            if await cursor.exists("captcha", target):
                await cursor.delete("captcha", target)
            target.update({"ChannelID": channel.id, "Mode": mode,
                           "RoleID": role_id, "Extras": extras})
            await cursor.insert_data("captcha", target)

    async def load(self, guild_id: int) -> tuple:
        async with self.db.get_cursor() as cursor:
            target = {"GuildID": guild_id}
            if await cursor.exists("captcha", target):
                if (row := await cursor.get_data("captcha", target)):
                    return row
            return ()


class Captcha(commands.Cog, DataManager):
    def __init__(self, bot):
        self.bot = bot
        self.captchas = {
            "image": ImageCaptcha(self),
            "word": WordCaptcha(self),
            "web": WebCaptcha(
                self,
                (self.bot.secret["test_hCaptcha"]
                    if bot.test else
                 self.bot.secret["hCaptcha"])
            )
        }
        self.sitekey = (
            "20000000-ffff-ffff-ffff-000000000002"
            if bot.test else
            "0a50268d-fa1e-405f-9029-710309aad1b0")
        self.queue_killer.start()

    @commands.command(
        aliases=["ca", "認証", "きゃぷちゃ", "auth", "cpic"],
        extras={
            "headding": {
                "ja": "画像認証, 合言葉認証, ウェブ認証をサーバーに設定します。",
                "en": "..."
            },
            "parent": "ServerSafety"
        }
    )
    @commands.has_permissions(administrator=True)
    @commands.cooldown(1, 10, commands.BucketType.guild)
    async def captcha(self, ctx, mode, *, role: discord.Role):
        """!lang ja
        --------
        認証を設定します。  
        認証を設定することでサーバーに参加した人がセルフBot(自動で動くユーザー)じゃないなら喋れるようにするといったことができます。  
        ※自動で動くユーザーの大半が荒らし目的で動いています。  
        またこの機能の合言葉認証を使うことで合言葉を知っている人のみがサーバーで喋ることができるなどのこともできます。  
        認証をするチャンネルはこのコマンドを実行したチャンネルに設定されるので、このコマンドはウェルカムメッセージが送信されるチャンネルで実行しましょう。

        Parameters
        ----------
        mode : image, web, 左の二つ以外の場合は合言葉
            設定する認証の種類です。  
            `image`が画像認証で実行したチャンネルに送信される画像にある数字を正しく入力するという認証です。  
            `web`がhCaptchaを利用したウェブでの本格認証です。  
            上記二つ以外を入力した場合はその入力した言葉を使った合言葉認証で設定されます。
        role : 役職名または役職のメンション
            認証成功時に付与する役職の名前またはメンションです。

        Examples
        --------
        `rt!captcha web @認証済み`  
        ウェブ認証で認証成功時には`認証済み`という役職を付与する用に設定します。

        Notes
        -----
        認証をするチャンネルは認証済みの人から見えないようにするのを推奨します。  
        そうすれば荒らしをする自動で動くユーザーが来た際に荒らしの影響を認証済みユーザーは受けません。  
        このコマンドを実行することができるのは管理者権限を持っている人のみです。

        !lang en
        --------
        ..."""
        extras = ""
        if mode not in self.captchas:
            extras = mode
            mode = "word"
        await self.save(ctx.channel, mode, role.id, extras)
        await ctx.reply("Ok")

    @commands.Cog.listener()
    async def on_ready(self):
        super(commands.Cog, self).__init__(
            await self.bot.mysql.get_database()
        )
        await self.init_table()

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member):
        row = await self.load(member.guild.id)
        if row:
            captcha = self.captchas[row[2]]
            await captcha.captcha(
                discord.utils.get(member.guild.text_channels, id=row[1]),
                member
            )

    def cog_unload(self):
        self.queue.killer.cancel()

    @tasks.loop(minutes=5)
    async def queue_killer(self):
        # 放置されて溜まってしまっている認証queueを削除する。
        now = time()
        for captcha in list(self.captchas.values()):
            for key in list(captcha.queue.keys()):
                if now - captcha.queue[key][1] > 1800:
                    del captcha.queue[key]

    @commands.Cog.route("/captcha")
    @OAuth.login_require()
    async def captcha_redirect(self, request):
        # ウェブ認証をする前に本人かどうかの確認をとるためにOAuth認証に通す。
        for guild_id in list(self.captchas["web"].queue.keys()):
            if self.captchas["web"].queue[guild_id][0] == request.ctx.user.id:
                guild = self.bot.get_guild(int(guild_id))
                if guild and guild.get_member(request.ctx.user.id):
                    userdata = self.captchas["web"].encrypt(
                        {"guild_id": guild.id, "user_id": request.ctx.user.id}
                    )
                    return await self.bot.web_manager.template(
                        "captcha.html", userdata=userdata, sitekey=self.sitekey
                    )
                else:
                    break
        raise SanicException(
            message="あなたが誰かどうか特定できませんでした。",
            status_code=403
        )


def setup(bot):
    bot.add_cog(Captcha(bot))