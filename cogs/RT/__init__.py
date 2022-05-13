# Free RT - Bot General

from __future__ import annotations

from traceback import TracebackException
from collections import defaultdict
from inspect import cleandoc
from itertools import chain
from random import choice
from io import StringIO
from os import listdir
from time import time
import speedtest

from discord.ext import commands, tasks
import discord

from jishaku.functools import executor_function

from util import RT

from data import PERMISSION_TEXTS

ERROR_CHANNEL = 962977145716625439

INFO_DESC = {
    "ja": """どうもFree RTという新時代Botです。
このBotは役職,投票,募集,チケットパネルやチャンネルステータスなどの定番機能はもちろん、声の変えれる読み上げやプレイリストのある音楽プレイヤーなどもある多機能Botです。
そして荒らし対策として使える画像,ウェブ,合言葉認証やスパム対策機能まであります。
またその他にもスレッド自動アーカイブ対策,自己紹介テンプレートに使える常に下にくるメッセージ,NSFW誤爆対策に使える自動画像スポイラーそしてボイスチャンネルロールなどあったら便利な機能もたくさんあります。
さあ是非このBotを入れて他のBotを蹴り飛ばしましょう！""",
    "en": """It's a new era Bot called Free RT.
This Bot is a multifunctional Bot with standard functions such as job title, voting, recruitment, ticket panel and channel status, as well as a music player with voice changing reading and playlists.
And there are images, web, password authentication and spam prevention functions that can be used as a troll countermeasure.
Other useful features include automatic thread archiving, always-on messages for self-introduction templates, an automatic image spoiler for NSFW detonation, and voice channel rolls.
Come on, let's put this Bot in and kick the other Bots."""
}
INFO_ITEMS = (("INVITE", {"ja": "招待リンク", "en": "invite link"}),
              ("SS", {"ja": "サポートサーバー", "en": "support server"}),
              ("URL", {"ja": "RTのウェブサイト", "en": "free-RT offical website"}),
              ("GITHUB", {"ja": "GitHub", "en": "GitHub"}),
              ("CREDIT", {"ja": "クレジット", "en": "Credit"}))
INFO_INVITE = "https://discord.com/api/oauth2/authorize?client_id=961521106227974174&permissions=8&scope=bot%20applications.commands"
INFO_SS, INFO_URL = "https://discord.gg/KW4CZvYMJg", "https://free-rt.com"
INFO_GITHUB = """* [free-RT-developers](https://github.com/free-RT)
* [RT-Bot](https://github.com/free-RT/rt-bot)
* [RT-Backend](https://github.com/free-RT/rt-backend)
* [RT-Frontend](https://github.com/free-RT/rt-frontend)"""
INFO_CREDIT = "[ここをご覧ください。](https://free-rt.com/credit.html)"

THANKYOU_TEMPLATE = cleandoc(
    """free-RTの導入ありがとうございます。
    よろしくお願いします。
    もし何かバグや要望があればウェブサイトから公式サポートサーバーにてお伝えください。

    **RT 情報**
    公式ウェブサイト：https://free-rt.com
    サポートサーバー：https://discord.gg/KW4CZvYMJg
    チュートリアル　：https://rt-team.github.io/ja/notes/tutorial
    プリフィックス　：`rf!`, `りふ！`, `RF!`, `rf.`, `Rf.`, `RF.`, `rF.`, `りふ.`, `Rf!`, `rF!`, `りふ!`

    **free-RT 利用規約**
    RTを利用した場合以下の利用規約に同意したことになります。
    https://free-rt.com/terms.html

    **free-RT プライバシーポリシー**
    RTのプライバシーポリシーは以下から閲覧可能です。
    https:/free-rt.com/privacy.html

    **If you do not understand Japanese**
    You can check what is written above in English by pressing the button at the bottom."""
)


class EnglishThxTemplateView(discord.ui.View):
    @discord.ui.button(label="See english version", custom_id="SeeEnglishVersionOfThx")
    async def sev(self, _, interaction: discord.Interaction):
        await interaction.response.send_message(
            cleandoc(
                """Thank you for inviting free-RT.
                If you have any bugs or requests, please let us know on the official support server via the website.
                You can also use `rf!lang en` to set the language to English.
                (If you want to set it for the whole server, run `rf!lang en server`.)

                **free-RT Info**.
                Official website: https://free-rt.com
                Support server: https://discord.gg/VHwJ3CBuWw
                Tutorial: https://free-rt.github.io/en/notes/tutorial
                Prefixes: `rf!`, `りふ！`, `RF!`, `rf.`, `Rf.`, `RF.`, `rF.`, `りふ.`, `Rf!`, `rF!`, `りふ!`

                **RT Terms of Service**.
                By using RT, you agree to the following terms of use.
                https://free-rt.com/terms.html

                **RT Privacy Policy**
                RT's privacy policy can be viewed at
                https://free-rt.com/privacy.html"""
            )
        )


class BotGeneral(commands.Cog):

    STATUS_TEXTS = (
        ("{}help | {} servers", lambda bot: len(bot.guilds)),
        ("{}help | {} users", lambda bot: len(bot.users))
    )

    def __init__(self, bot: RT):
        self.bot, self.rt = bot, bot.data
        self.errors = set()

        if not hasattr(self, "thx_view"):
            self.thx_view = EnglishThxTemplateView(timeout=None)
            self.bot.add_view(self.thx_view)

        self.wslatency = "..."
        self.cache: defaultdict[int, dict[str, float]] = defaultdict(dict)
        self.remove_cache.start()
        self.error_log_to_discord.start()

        self.make_embed_template()

    def make_embed_template(self):
        self._now_status_index = 0
        self._start_time = time()
        self.status_updater.start()

    def _get_ping(self) -> str:
        # pingを返します。
        return "%.1f" % round(self.bot.latency * 1000, 1)

    def cog_unload(self) -> None:
        self.status_updater.cancel()
        self.remove_cache.cancel()

    @tasks.loop(seconds=60)
    async def status_updater(self) -> None:
        # RTのステータスを更新するループです。
        await self.bot.wait_until_ready()

        await self.bot.change_presence(
            activity=discord.Activity(
                name=(now := self.STATUS_TEXTS[self._now_status_index])[0].format(self.bot.command_prefix[0], now[1](self.bot)),
                type=discord.ActivityType.watching, state="Free-RT Bot",
                details=f"PING：{self._get_ping()}\n絶賛稼働中...",
                timestamps={"start": self._start_time},
                buttons={"label": "free-RTのホームページに行く！", "url": "https://rt-bot.com/"}
            )
        )

        self._now_status_index = 0 if self._now_status_index else 1

    @commands.command(
        extras={"headding": {"ja": "レイテンシを表示します。", "en": "Show you free-RT latency."},
                "parent": "RT"},
        slash_command=True,
        description="レイテンシを表示します。 / Show you free-RT latency."
    )
    @commands.cooldown(1, 10, commands.BucketType.user)
    async def ping(self, ctx):
        """!lang ja
        --------
        RTのレイテンシを表示します。  
        返信された数字が400以降だとネット回線が悪いです。

        !lang en
        --------
        You can view free-RT latency.  
        If latency is over to 400, network is bad."""
        embed = discord.Embed(
            title={
                "ja": "現在のfree-RTのレイテンシ",
                "en": "Latency of current free-RT"
            }, color=self.bot.Colors.normal
        )
        embed.add_field(
            name="Discord Connection Latency",
            value=f"{self._get_ping()}ms"
        )
        # Backendとの通信状況を調べる。
        embed.add_field(
            name="Backend Connection Latency",
            value="%.1fms" % self.bot.cogs["RTLife"].data["backendLatency"][-1]
        )
        await ctx.reply(embed=embed)

    @executor_function
    def _speedtest(self):
        st = speedtest.Speedtest()
        st.get_best_server()
        st.download()
        st.upload()
        return st.results.dict()

    @commands.command(
        extras={"headding": {
            "ja": "回線速度テストします",
            "en": "Do a speed test"
        }, "parent": "RT"},
        aliases=["st"]
    )
    @commands.cooldown(1, 10800, commands.BucketType.guild)
    async def speedtest(self, ctx):
        embed = discord.Embed(
            title="速度回線テスト", description="測定中です...", color=self.bot.Colors.normal
        )
        message = await ctx.send(embed=embed)
        data = await self._speedtest()
        embed = discord.Embed(title="速度回線テスト")
        embed.add_field(name="ダウンロード", value=f'{data["download"]/1048576}Mbps')
        embed.add_field(name="アップロード", value=f'{data["upload"]/1048576}Mbps')
        await message.edit(embed=embed)

    @commands.command(
        extras={"headding": {
            "ja": "free-RTの招待リンクを含めた情報を表示します。",
            "en": "Show you RT's invite link."
        }, "parent": "RT"},
        aliases=["credit", "invite", "about", "情報", "じょうほう"]
    )
    async def info(self, ctx):
        """!lang ja
        --------
        free-RTの情報を表示します。  
        free-RTの基本情報(招待リンク,ウェブサイトURL)やクレジットなどを確認することができます。  

        !lang en
        --------
        Show you free-RT's information.  
        It inclued invite link."""
        embed = discord.Embed(
            title={"ja": "free-RTの情報", "en": "free-RT information"},
            description=INFO_DESC,
            color=self.bot.colors["normal"]
        )
        embed.add_field(
            name={"ja": "サーバー数", "en": "Servers"},
            value=len(self.bot.guilds),
            inline=False
        )
        embed.add_field(
            name={"ja": "ユーザー数", "en": "Users"},
            value=len(self.bot.users),
            inline=False
        )
        for item_variable_name, item_name in INFO_ITEMS:
            embed.add_field(
                name=item_name, value=eval("INFO_" + item_variable_name),
                inline=False
            )
        await ctx.reply(embed=embed)

    @tasks.loop(seconds=5)
    async def remove_cache(self):
        # クールダウンを一度送信したら次送信しないようにするために使うキャッシュの期限切れの削除をする。
        now = time()
        for aid, cmds in list(self.cache.items()):
            for cmd, timeout in list(cmds.items()):
                if now > timeout:
                    del self.cache[aid][cmd]

    @commands.Cog.listener()
    async def on_command_error(self, ctx: commands.Context, error: Exception):
        # エラー時のメッセージ。翻訳はdescriptionのみ。
        kwargs, color = {}, self.bot.colors["error"]
        if isinstance(error, commands.CommandNotFound):
            # 実行しようとしたコマンドを考える。
            suggestion = f"`{suggestion}`" if (
                suggestion := "`, `".join(
                    command.name for command in self.bot.commands
                    if any(
                        any(
                            len(cmd_name[i:i + 3]) > 2
                            and cmd_name[i:i + 3] in ctx.message.content
                            for i in range(3)
                        ) for cmd_name in chain(
                            (command.name,), command.aliases
                        )
                    )
                )
            ) else "?"
            title = "404 Not Found"
            description = {
                "ja": "そのコマンドが見つかりませんでした。\n"
                      f"`rf!help <word>`で検索が可能です。\nもしかして：{suggestion}",
                "en": f"It can't found that command.\n`rf!help <word>`This can search command.\nSuggetion:{suggestion}"}
            color = self.bot.colors["unknown"]
        elif isinstance(error, discord.Forbidden):
            title = "500 Internal Server Error"
            description = {
                "ja": "Free-RTに権限がないため正常にコマンドを実行できませんでした。",
                "en": "The command could not be executed successfully because Free-RT does not have permissions."
            }
        elif isinstance(error, commands.CommandOnCooldown):
            if (ctx.command.qualified_name in self.cache.get(ctx.author.id, {})
                    and not hasattr(ctx, "__setting_context__")):
                return
            else:
                title = "429 Too Many Requests"
                description = {
                    "ja": (
                        "現在このコマンドはクールダウンとなっています。\n"
                        + "{:.2f}秒後に実行できます。".format(error.retry_after)
                    ), "en": (
                        "Currently, this command is on cooldown.\n"
                        + "You can do this command after {:.2f} seconds.".format(error.retry_after)
                    )
                }
                self.cache[ctx.author.id][ctx.command.qualified_name] = \
                    time() + error.retry_after
                color = self.bot.colors["unknown"]
        elif isinstance(error, (commands.MemberNotFound,
                        commands.UserNotFound)):
            title = "400 Bad Request"
            description = {"ja": f"指定されたユーザー:{error.argument}が見つかりませんでした。",
                           "en": f"The user not found:{error.argument}."}
        elif isinstance(error, commands.ChannelNotFound):
            title = "400 Bad Request"
            description = {"ja": f"指定されたチャンネル:{error.argument}が見つかりませんでした。",
                           "en": f"The channel not found:{error.argument}."}
        elif isinstance(error, commands.RoleNotFound):
            title = "400 Bad Request"
            description = {"ja": f"指定されたロール:{error.argument}が見つかりませんでした。",
                           "en": f"The role not found:{error.argument}."}
        elif isinstance(error, commands.BadBoolArgument):
            title = "400 Bad Request"
            description = {"ja": ("指定された真偽値が無効です。\n"
                                  + "有効な真偽値：`on/off`, `true/false`, `True/False`"),
                           "en": ("The specified boolean value is invalid\n"
                                  + "Valid boolean value:`on/off`, `true/false`, `True/False`")}
        elif isinstance(error, commands.MissingRequiredArgument):
            title = "400 Bad Request"
            description = {"ja": f"引数{error.param.name}が足りないためコマンドを実行できません。",
                           "en": f"{error.param.name} is a required argument that is missing."}
        elif isinstance(
            error, (commands.BadArgument,
                    commands.ArgumentParsingError,
                    commands.TooManyArguments,
                    commands.BadUnionArgument,
                    commands.BadLiteralArgument)
        ):
            title = "400 Bad Request"
            description = {
                "ja": f"コマンドの引数が適切ではありません。\nまたは必要な引数が足りません。\nCode:`{error}`",
                "en": "It's command's function is bad."
            }
        elif isinstance(error, commands.MissingPermissions):
            title = "403 Forbidden"
            description = {
                "ja": "あなたの権限ではこのコマンドを実行することができません。\n**実行に必要な権限**\n"
                      + ", ".join(
                          f"`{PERMISSION_TEXTS.get(name, name)}`"
                          for name in error.missing_permissions
                      ),
                "en": "You can't do this command.\n**You need these permissions**\n`"
                      + "`, `".join(error.missing_permissions) + "`"
            }
        elif isinstance(error, commands.MissingRole):
            title = "403 Forbidden"
            description = {
                "ja": f"あなたはこのコマンドの実行に必要な役職:{error.missing_role}を持っていないため、このコマンドを実行できません。",
                "en": f"You have to have the role:{error.argument} to run this command."}
        elif isinstance(error, commands.CheckFailure):
            title = "403 Forbidden"
            description = {
                "ja": "あなたはこのコマンドを実行することができません。",
                "en": "You can't do this command."}
        elif isinstance(error, AssertionError):
            title = "400 Bad Request"
            description = error.args[0]
        elif isinstance(error, commands.CommandInvokeError):
            return await self.on_command_error(ctx, error.original)
        elif isinstance(error, AttributeError) and "VoiceChannel" in str(error):
            title = "400 Bad Request"
            description = {
                "ja": "ボイスチャンネルにメッセージを送信できませんでした。",
                "en": "I couldn't send to a voice channel."
            }
        else:
            error_message = "".join(
                TracebackException.from_exception(error).format()
            )
            self.errors.add(error_message)

            print(error_message)

            title = "500 Internal Server Error"
            description = {
                "ja": ("コマンドの実行中にエラーが発生しました。\n"
                       + f"```python\n{error_message}\n```"),
                "en": ("I made an error!\n"
                       + f"```python\n{error_message}\n```"),
            }

            kwargs["view"] = discord.ui.View()
            kwargs["view"].add_item(
                discord.ui.Button(
                    label="サポートサーバー / SupportServer", url=INFO_SS
                )
            )

        if (length := len(description)) > 4096:
            description = description[4096 - length + 1:]
        if "400" in title:
            # 引数がおかしい場合はヘルプボタンを表示する。
            if (url := self.get_command_url(ctx.command)):
                kwargs["view"] = discord.ui.View()
                kwargs["view"].add_item(
                    discord.ui.Button(
                        label="ヘルプを見る", emoji="❔", url=url
                    )
                )

        kwargs["embed"] = discord.Embed(
            title=title, description=description, color=color
        )
        try:
            await ctx.reply(**kwargs)
        except Exception as e:
            kwargs["content"] = str(e)
            await ctx.send(**kwargs)

    @tasks.loop(hours=2)
    async def error_log_to_discord(self):
        # discordの特定のチャンネルにエラーを送信します。
        if len(self.errors) == 0:
            return
        await self.bot.get_channel(ERROR_CHANNEL).send(
            embed=discord.Embed(title="エラーログ", description=f"この2時間に発生したエラーの回数:{len(self.errors)}"),
            file=discord.File(StringIO("\n\n".join(self.errors)), "erros.txt")
        )
        self.errors = set()

    def get_help_url(self, category: str, name: str) -> str:
        return f"https://free-rt.com/help.html?g={category}&c={name}"

    def get_command_url(self, command: commands.Command) -> str:
        "渡されたコマンドのヘルプのURLを返します。"
        for name in self.bot.cogs["Help"].CATEGORIES:
            if self.bot.cogs["Help"].CATEGORIES[name] == command.extras.get(
                "parent", command.__original_kwargs__.get("parent", "")
            ):
                return self.get_help_url(name, command.name)
        return ""

    @commands.Cog.listener()
    async def on_guild_join(self, guild: discord.Guild):
        try:
            await guild.owner.send(THANKYOU_TEMPLATE, view=self.thx_view)
        except Exception:
            tentative = None
            for channel in guild.text_channels:
                if "bot" in channel.name:
                    tentative = channel
                    break
                elif any(word in channel.name for word in ("雑談", "general")):
                    tentative = channel
            else:
                if tentative is None:
                    tentative = choice(guild.text_channels)
            await tentative.send(THANKYOU_TEMPLATE, view=self.thx_view)


async def setup(bot):
    await bot.add_cog(BotGeneral(bot))
    for name in listdir("cogs/RT"):
        if not name.startswith(("_", ".")):
            try:
                await bot.load_extension(
                    f"cogs.RT.{name[:-3] if name.endswith('.py') else name}")
            except Exception as e:
                print(e)
            else:
                bot.print("[Extension]", "Loaded", name)  # ロードログの出力
