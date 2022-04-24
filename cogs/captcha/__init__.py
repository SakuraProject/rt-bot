# Free RT - Captcha

from __future__ import annotations

from typing import TypedDict, Literal, Union, Optional, Any

from collections import defaultdict
from dataclasses import dataclass
from time import time

from discord.ext import commands, tasks
import discord

from ujson import dumps

from util import RT, Table

from .image import ImageCaptcha, QueueData as ImageQueue
from .web import WebCaptcha
from .word import WordCaptcha
from .click import ClickCaptcha


Mode = Literal["image", "web", "word"]


@dataclass
class Captchas:
    image: ImageCaptcha
    word: WordCaptcha
    web: WebCaptcha
    click: ClickCaptcha


class Timeout(TypedDict):
    kick: bool
    time: float


class WordData(TypedDict):
    word: str
    channel_id: int


class Extras(TypedDict, total=False):
    timeout: Timeout
    data: Union[WordData, Any]


@dataclass
class QueueData:
    mode: Mode
    role_id: int
    extras: Extras


class CaptchaSaveData(Table):
    __allocation__ = "GuildID"
    mode: Mode
    role_id: int
    extras: Extras


class DataManager:
    "セーブデータを管理するためのクラスです。"

    def __init__(self, cog: Captcha):
        self.cog, self.data = cog, CaptchaSaveData(cog.bot)

    def write(
        self, guild_id: int, mode: Mode, role_id: int, extras: Extras
    ) -> None:
        "認証設定を保存します。"
        self.data[guild_id].mode = mode
        self.data[guild_id].role_id = role_id
        self.data[guild_id].extras = extras

    def read(self, guild_id: int) -> Optional[tuple[Mode, int, Extras]]:
        "認証設定を読み込みます。"
        if "mode" in self.data[guild_id]:
            return self.data[guild_id].mode, self.data[guild_id].role_id, \
                self.data[guild_id].extras

    def delete(self, guild_id: int) -> None:
        "認証の設定を削除します。"
        assert self.read(guild_id), "設定されていません。"
        del self.data[guild_id]

    def timeout(self, guild_id: int, time_: float, kick: bool) -> None:
        "認証設定にタイムアウトを設定します。"
        assert (row := self.read(guild_id)), "設定がありません。"
        data = row[-1]
        data["timeout"] = {"time": time_, "kick": kick}
        self.data[guild_id].extras = data


class View(discord.ui.View):
    "認証開始ボタンのViewです。"

    def __init__(self, cog: Captcha, emoji: Optional[str] = None, *args, **kwargs):
        self.cog = cog
        super().__init__(*args, **kwargs)
        if emoji is not None:
            self.children[0].emoji = emoji

    @discord.ui.button(label="Start Captcha", custom_id="captcha", emoji="🔎")
    async def start_captcha(self, _, interaction: discord.Interaction):
        if self.cog.queued(interaction.guild_id, interaction.user.id):
            if (row := self.cog.read(interaction.guild_id)):
                # もし認証の設定がされているサーバーなら認証を開始する。
                if hasattr(captcha := self.cog.get_captcha(row[0]), "on_captcha"):
                    await captcha.on_captcha(interaction)
                else:
                    await interaction.response.send_message(
                        "このサーバーで設定されている認証の種類がこのボタンを押す方式とあっていません。",
                        ephemeral=True
                    )
            else:
                await interaction.response.send_message(
                    "このサーバーで認証の設定がされていないので認証を開始することができません。",
                    ephemeral=True
                )
        else:
            await interaction.response.send_message(
                "あなたは認証対象ではありません。\n放置した場合こうなります。\nもしなぜこうなるのかわからないのなら以下をご覧ください。\nhttps://rt-team.github.io/ja/trouble/captcha", ephemeral=True
            )


QueueDataT = Union[QueueData, ImageQueue]


class Captcha(commands.Cog, DataManager):

    BASE = "/api/captcha/"

    def __init__(self, bot: RT):
        self.bot = bot
        self.queue: defaultdict[
            int, dict[int, tuple[float, bool, QueueDataT]]
        ] = defaultdict(dict)
        self.queue_remover.start()
        if hasattr(self.bot, "_captcha_view"):
            self.view = self.bot._captcha_view
            self.view.cog = self
        else:
            self.bot._captcha_view = self.view = View(self, timeout=None)
            self.bot.add_view(self.view)
        self.captchas = Captchas(
            ImageCaptcha(self), WordCaptcha(self),
            WebCaptcha(self), ClickCaptcha(self)
        )
        super(commands.Cog, self).__init__(self)

    def session(self):
        "`aiohttp.ClientSession`を手に入れるためのものです。"
        return self.bot.session

    def print(self, *args, **kwargs) -> None:
        return self.bot.print("[Captcha]", *args, **kwargs)

    @commands.group(
        aliases=["auth", "cta", "認証"], extras={
            "headding": {
            "ja": "認証機能", "en": "Captcha"
            }, "parent": "ServerSafety"
        }
    )
    @commands.has_guild_permissions(manage_roles=True)
    async def captcha(self, ctx: commands.Context):
        """!lang ja
        --------
        認証機能です。  
        [セルフBot](https://rt-team.github.io/ja/notes/what_is_self_bot)による荒らし対策に有効です。

        Warnings
        --------
        このコマンドを設定する前から参加している人は認証対象とならないので、手動で役職を付与してください。  
        そしてデフォルトではサーバー参加後に一時間放置すると認証対象から外されます。  
        もし認証対象から外されるまでの時間を変えたり外された際にキックをするかどうかの設定をする場合は`timeout`を設定してください。  
        (下の方にヘルプがあります。)

        Notes
        -----
        上手くいかない際は[こちら](https://rt-team.github.io/ja/trouble/captcha)と[こちら](https://rt-team.github.io/ja/trouble/role)をご確認ください。

        !lang en
        --------
        Captcha function.  
        This is effective in preventing vandalism by self-bots spamming.

        Warnings
        --------
        People who have joined before you set this command will not be authenticated, so you will have to manually grant them a position.  
        By default, if you leave the server for an hour after joining, you will be deauthenticated.  
        If you want to specify how long it takes to be deauthorized, or if you want to kick people when they are deauthorized, set the `timeout`.  
        (Help is available at the bottom of this page.)

        Notes
        -----
        If it does not work, please check [this](https://rt-team.github.io/en/trouble/captcha) and [this](https://rt-team.github.io/en/trouble/role)"""
        if not ctx.invoked_subcommand:
            await ctx.reply(
                {"ja": "使用方法が違います。", "en": "It is wrong way to use this command."}
            )

    async def setting(
        self, ctx: commands.Context, mode: Mode, role_id: int,
        extras: Extras, panel: bool = True, **kwargs
    ) -> discord.Message:
        "認証を設定しオプションでパネルを送信するための関数です。"
        await ctx.trigger_typing()
        self.write(ctx.guild.id, mode, role_id, extras)
        if panel:
            return await ctx.send(
                embed=discord.Embed(
                    **kwargs, color=self.bot.Colors.normal
                ), view=self.view
            )
        else:
            return await ctx.reply("Ok")

    BELLOW = {
        "ja": "以下のボタンを押すことで認証を開始することができます。",
        "en": "Press the button bellow to start image captcha."
    }

    @captcha.command(aliases=["画像", "img"])
    async def image(self, ctx: commands.Context, *, role: discord.Role):
        """!lang ja
        --------
        画像認証を設定します。  
        画像認証は画像にある読みづらい数字を選択して人間かどうかをチェックするものです。

        <ja-ext>

        !lang en
        --------
        Setting Image Captcha  
        Image captcha checks whether a person is human by selecting an illegible number on an image.

        <en-ext>"""
        await self.setting(
            ctx, "image", role.id, {}, title={
                "ja": "画像認証", "en": "Image Captcha"
            }, description=self.BELLOW
        )

    @captcha.command(aliases=["合言葉", "wd"])
    async def word(self, ctx: commands.Context, word: str, *, role: discord.Role):
        """!lang ja
        --------
        合言葉認証を設定します。  
        合言葉認証はこの設定コマンドを実行したチャンネルにサーバーの参加者は設定した合言葉を送信しないといけないもので、合言葉さえ知れば誰でも入れるためセキュリティはあまり高くありません。

        Parameters
        ----------
        word : 合言葉
            言わないといけない言葉です。
        role : 役職のメンションか名前またはID
            認証成功時に付与する役職です。

        !lang en
        --------
        Configure password captcha.  
        The password captcha requires the server participants to send the configured password to the channel where this configuration command is executed, and it is not a function to check whether the participants are human or not, but rather a function to set up a private server.

        Parameters
        ----------
        word : password
            A word that must be said.
        role : Mention, name or ID of the role
            The role to be assigned upon successful captcha."""
        await self.setting(
            ctx, "word", role.id, {
                "data": {"word": word, "channel_id": ctx.channel.id}
            }, False
        )

    @captcha.command(aliases=["ウェブ", "wb"])
    async def web(self, ctx: commands.Context, *, role: discord.Role):
        """!lang ja
        --------
        ウェブ認証を設定します。  
        これは画像認証と違ってウェブサイトでhCaptchaを使用して人間チェックを行うとても本格的な認証です。

        <ja-ext>

        !lang en
        --------
        Configure web captcha.  
        Unlike image captcha, this is a very serious form of captcha that uses hCaptcha to perform human checks on websites.

        <en-ext>"""
        await self.setting(
            ctx, "web", role.id, {}, title={
                "ja": "ウェブ認証", "en": "Web Captcha"
            }, description=self.BELLOW
        )

    @captcha.command(aliases=["ボタン", "クリック", "c"])
    async def click(self, ctx: commands.Context, *, role: discord.Role):
        """!lang ja
        --------
        ワンクリック認証でボタンをクリックするだけの認証方法です。  
        セキュリティの強度は弱くなります。

        <ja-ext>

        !lang en
        --------
        One-click captcha is an authentication method that requires only the click of a button.  
        The strength is weak.

        <en-ext>"""
        await self.setting(
            ctx, "click", role.id, {}, title={
                "ja": "ワンクリック認証", "en": "One Click Captcha"
            }, description={
                "ja": "役職を手に入れるには以下のボタンを押してください。",
                "en": "To get the roll, press the button below."
            }
        )

    @captcha.command(aliases=["o", "オフ", "無効"])
    async def off(self, ctx: commands.Context):
        """!lang ja
        --------
        設定した認証をオフにします。

        !lang en
        --------
        Turn off the captcha you have set up."""
        try:
            self.delete(ctx.guild.id)
        except AssertionError:
            await ctx.reply(
                {"ja": "既に認証設定はオフになっています。",
                 "en": "The authentication setting is already turned off."}
            )
        else:
            if ctx.guild.id in self.queue:
                del self.queue[ctx.guild.id]
            await ctx.reply("Ok")

    @captcha.command("timeout", aliases=["タイムアウト", "t"])
    async def timeout_(self, ctx: commands.Context, timeout: float, kick: bool):
        """!lang ja
        --------
        認証のタイムアウトをカスタマイズします。  
        そしてオプションでタイムアウト時にキックするかどうかを設定します。

        Notes
        -----
        これのデフォルトは一時間で認証ができなくなりキックはされません。  
        タイムアウトは認証の設定を変更すると設定がリセットされます。

        Parameters
        ----------
        timeout : float
            何分たったらタイムアウトするかです。
        kick : bool
            キックをするかどうかです。

        !lang en
        --------
        Set a custom captcha timeout.  
        And optionally set whether or not to kick on timeout.

        Notes
        -----
        The default for this is that captcha will fail after one hour and no kick will be performed.  
        The timeout setting will be reset when the authentication setting is changed.

        Parameters
        ----------
        timeout : float
            The number of minutes to timeout.
        kick : bool
            Whether to kick or not."""
        if 1 <= timeout <= 180:
            try:
                self.timeout(ctx.guild.id, timeout, kick)
            except AssertionError:
                await ctx.reply(
                    {"ja": "このサーバーは認証の設定がされていないので、タイムアウトを設定することができません。",
                     "en": "I couldn't set a timeout because it was not set the captcha setting yet."}
                )
            else:
                await ctx.reply("Ok")
        else:
            await ctx.reply(
                {"ja": "タイムアウトは一分から三時間の範囲内である必要があります。",
                 "en": "Timeout must be set from one minute to three hours."}
            )

    def get_captchas(self) -> map:
        return map(lambda x: getattr(self.captchas, x), dir(self.captchas))

    async def dispatch(self, captcha: object, name: str, *args, **kwargs) -> Optional[Any]:
        # 各Captchaクラスにある関数をあれば実行します。
        if hasattr(captcha, name):
            return await getattr(captcha, name)(*args, **kwargs)

    def queued(self, guild_id: int, member_id: int) -> bool:
        # 渡されたIDがqueueとしてキャッシュされているかを確認します。
        return guild_id in self.queue and member_id in self.queue[guild_id]

    async def remove_queue(
        self, guild_id: int, member_id: int, data: Optional[QueueDataT] = None
    ) -> None:
        "Queueを削除します。"
        if data is None:
            data = self.queue[guild_id][member_id][2]
        for captcha in self.get_captchas():
            await self.dispatch(captcha, "on_queue_remove", guild_id, member_id, data)
        del self.queue[guild_id][member_id]
        if not self.queue[guild_id]:
            del self.queue[guild_id]

    def cog_unload(self):
        self.queue_remover.cancel()

    @tasks.loop(seconds=10)
    async def queue_remover(self):
        # タイムアウトしたキューを消すためのループです。
        now = time()
        for guild_id, members in list(self.queue.items()):
            for member_id, (time_, kick, data) in list(members.items()):
                data: QueueDataT
                if now >= time_:
                    # もしキック設定がされている場合はキックを行う。
                    if (kick and (guild := self.bot.get_guild(guild_id))
                            and (member := guild.get_member(member_id))):
                        if not member.get_role(data.role_id):
                            try:
                                await member.kick(reason="[Captcha] Timeout")
                            except Exception:
                                ...
                    # キューの削除を行う。
                    self.bot.loop.create_task(self.remove_queue(guild_id, member_id, data))

    def get_captcha(self, mode: Mode) -> Union[
        ImageCaptcha, WordCaptcha, WebCaptcha, ClickCaptcha
    ]:
        return getattr(self.captchas, mode)

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member):
        if (member.id not in self.queue.get(member.guild.id, {})
                and (row := self.read(member.guild.id)) and not member.bot):
            # もし認証が設定されているサーバーの場合はqueueにタイムアウト情報を追加しておく。
            self.queue[member.guild.id][member.id] = (
                time() + row[2].get("timeout", {}).get("time", 60) * 60,
                row[2].get("timeout", {}).get("kick", False),
                QueueData(row[0], row[1], row[2])
            )
            # もしCpatchaクラスにon_member_joinがあるならQueueDataに値を設定できるようにそれを呼び出す。
            await self.dispatch(self.get_captcha(row[0]), "on_member_join", member)

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        # 合言葉認証に必要なのでon_messageを呼び出しておく。
        if (message.guild and message.author
                and self.queued(message.guild.id, message.author.id)):
            await self.dispatch(
                self.get_captcha(
                    self.queue[message.guild.id][message.author.id][2].mode
                ), "on_message", message
            )


# ヘルプに認証ボタンについての追記をする。
for fname in ("image", "web", "click"):
    function = getattr(Captcha, fname)
    function._callback.__doc__ = function._callback.__doc__.replace(
        "<ja-ext>", """Parameters
        ----------
        role : 役職の名前かメンションまたはID
            認証成功時に付与する役職です。  
            この役職を手に入れないと通常のチャンネルを見れないようにするのをおすすめします。

        Notes
        -----
        この認証を設定すると認証開始ボタンのついたメッセージが実行したチャンネルに送信されます。  
        サーバーに参加した人はそのボタンを押して認証を開始します。  
        ですので認証チャンネルではメッセージが送信できないようにしましょう。""", 1
    ).replace(
        "<en-ext>", """Parameters
        ----------
        role : Name, Mention or ID of the role.
            This is the role that will be given upon successful captcha.  
            If you don't get this role, you can't view the normal channel.

        Notes
        -----
        When this captcha is set up, a message with a button to start captcha will be sent to the channel where it was executed.  
        People who join the server will press that button to start captcha.  
        So, make sure that no message is sent to the captcha channel.""", 1
    )
del function, fname


def setup(bot):
    bot.add_cog(Captcha(bot))
