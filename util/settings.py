# Free RT Dashboard - Setting

from __future__ import annotations

from typing import Union, Optional, Literal, overload, get_origin, get_args

from asyncio import Event, wait_for, TimeoutError as AioTimeoutError
from datetime import datetime

from discord.ext import commands
import discord

from pytz import utc

from util.rt_module.src.setting import CommandData, CommandRunData
from . import RT
from .olds import clean_content


def _replaceln(content: str) -> str:
    return content.replace("\n", "  ")


class Context:
    "ダッシュボードから呼ばれたコマンドで実行されるContextです。"

    def __init__(
        self, cog: SettingManager, data: CommandRunData,
        command: commands.Command, **kwargs
    ):
        # IDを文字列から整数に変換する。
        for key, value in list(data.items()):
            if key.endswith("id"):
                data[key] = int(value)

        # 変数を作っていく。
        self.data = data
        self.setting_manager = cog
        self.bot: "RT" = self.setting_manager.bot
        self.guild: Optional[discord.Guild] = self.bot.get_guild(data["guild_id"])
        self.created_at: datetime = datetime.now(utc)
        self.edited_at = None
        self.__setting_context__ = True

        self.channel: Optional[discord.TextChannel] = self.guild.get_channel(
            int(data["channel_id"])
        )
        self.author: Union[discord.User, discord.Member] = (
            self.guild.get_member(data["user_id"]) if self.guild
            else self.bot.get_user(data["user_id"])
        )
        for key in kwargs:
            setattr(self, key, kwargs.pop(key, None))
        self.command = command
        self.cog = command.cog
        self.voice_client: Optional[discord.VoiceClient] = \
            getattr(self.guild, "voice_client", None)
        self.prefix = "r2!" if self.bot.test else "rt!"
        self.me: Union[discord.Member, discord.ClientUser] = \
            getattr(self.guild, "me", self.bot.user)
        self.message = self
        self.reply = self.send
        self.replied = Event()
        self.replied_content: Optional[str] = None

    async def trigger_typing(self):
        ...

    async def send(
        self, content: str = None, embed: discord.Embed = None, *args, **kwargs
    ):
        "返信をします。"
        self.replied_content = self.bot.cogs["Language"].get_text(
            embed if embed else content, self.author.id
        )
        if isinstance(self.replied_content, discord.Embed):
            embed = "\n"
            if self.replied_content.title:
                embed += f"# {self.replied_content.title}"
            if self.replied_content.description:
                embed += f"\n{_replaceln(self.replied_content.description)}"
            for field in self.replied_content.fields:
                embed += f"\n## {field.name}\n{_replaceln(field.value)}"
            if self.replied_content.footer:
                embed += f"\n{self.replied_content.footer.text}"
            self.replied_content = embed
        if self.guild is not None:
            self.replied_content = clean_content(self.replied_content, self.guild)
        self.bot.print(
            "[SettingManager]", "[Reply]",
            f"Command: {self.command}, Author: {self.author}, Guild: {self.guild}, Channel: {self.channel}"
        )
        self.replied.set()

    @overload
    async def reply(
        self, content: str = None, embed: discord.Embed = None, *args, **kwargs
    ):
        ...

    async def delete(self) -> None:
        ...


class SettingManager(commands.Cog):
    def __init__(self, bot: RT):
        self.bot = bot
        self.data: dict[str, CommandData] = {}
        self.helps: dict[str, dict[str, str]] = {}
        self.commands: dict[str, commands.Command] = {}
        self.bot.rtws.set_event(self.get_help)
        self.bot.rtws.set_event(self.run, "dashboard.run")

    def session(self):
        "`aiohttp.ClientSession`の準備をする。"
        return self.bot.session

    def _get_default(self, default: object) -> object:
        # 渡されたものがスラッシュのオプションならそれに設定されているデフォルトを返す。
        return default.default if isinstance(default, discord.SlashOption) else default

    async def get_help(self, name: str) -> Optional[str]:
        "ヘルプを取得します。RTWSで使うためのものです。"
        return self.helps.get(name)

    def extract_category(self, command: commands.Command) -> str:
        "カテゴリーを取り出します。"
        return command.extras.get("parent", "Other")

    def extract_help(self, command: commands.Command, category: str) -> dict[str, str]:
        "ヘルプを取り出します。"
        return self.bot.cogs["DocHelp"].data[category].get(
            command.qualified_name[command.qualified_name.find(" "):]
            if command.parent else command.name
        )

    def check_parent(self, command: commands.Commande) -> bool:
        "親コマンドがダッシュボードに追加しても良いものかどうかをチェックします。"
        return "headding" in command.extras

    @commands.Cog.listener()
    async def on_command_add(self, command: discord.Command):
        # コマンドのデータを用意する。
        if self.check_parent(command) or command.parent is not None:
            # ヘルプとカテゴリーを取り出す。
            if command.parent is None:
                category = self.extract_category(command)
                try:
                    self.helps[command.qualified_name] = self.bot.cogs["BotGeneral"] \
                        .get_command_url(command)
                except KeyError:
                    self.helps[command.qualified_name] = "#"
            else:
                tentative = command.parent
                while tentative.parent is not None:
                    tentative = tentative.parent
                if self.check_parent(tentative):
                    self.helps[command.qualified_name] = self.bot.cogs["BotGeneral"] \
                        .get_command_url(tentative)
                else:
                    return
            # kwargsを準備する。
            kwargs = {}
            for parameter in command.clean_params.values():
                kwargs[parameter.name] = {
                    "type": "str",
                    "default": (
                        None if parameter.default == parameter.empty
                        else self._get_default(parameter.default)
                    ),
                    "extra": None
                }
                if parameter.annotation in (
                    discord.TextChannel, discord.VoiceChannel, discord.Thread,
                    discord.Role, discord.Member, discord.User, discord.Guild
                ):
                    if parameter.annotation.__name__.endswith("Channel"):
                        kwargs[parameter.name]["type"] = "Channel"
                    elif parameter.annotation.__name__ in ("User", "Member"):
                        kwargs[parameter.name]["type"] = "User"
                    else:
                        kwargs[parameter.name]["type"] = parameter.annotation.__name__
                elif parameter.annotation == bool:
                    kwargs[parameter.name]["type"] = "Literal"
                    kwargs[parameter.name]["extra"] = ("on", "off")
                elif get_origin(parameter.annotation) is Literal:
                    kwargs[parameter.name]["type"] = "Literal"
                    kwargs[parameter.name]["extra"] = get_args(parameter.annotation)
            # データに格納する。
            self.data[command.qualified_name] = CommandData(kwargs=kwargs)
            if command.parent is None:
                self.data[command.qualified_name]["headding"] = command.extras.get("headding")
                self.data[command.qualified_name]["category"] = category
            self.data[command.qualified_name]["help"] = self.helps[command.qualified_name]
            # コマンドを保存しておく。
            self.commands[command.qualified_name] = command

    def reset(self) -> None:
        "データをリセットします。"
        self.data, self.commands, self.helps = {}, {}, {}

    @commands.Cog.listener()
    async def on_update_api(self):
        try:
            await wait_for(self.bot.rtws.wait_until_ready(), timeout=10)
        except AioTimeoutError:
            ...
        else:
            await self.bot.rtws.request("dashboard.update", self.data)

    async def run(self, data: CommandRunData) -> tuple[Literal["Error", "Ok"], str]:
        "コマンドを走らせます。"
        ctx = None
        try:
            # コマンドのメッセージを組み立てる。
            content = f"{self.bot.command_prefix[0]}{data['name']}"
            for parameter in self.commands[data["name"]].clean_params.values():
                tentative = f' "{data["kwargs"].get(parameter.name, "")}"'
                if parameter.kind == parameter.KEYWORD_ONLY:
                    tentative = f" {tentative[2:-1]}"
                content += tentative

            # 実行できるかチェックをしてからオリジナルContextでコマンドを実行する。
            ctx = Context(self, data, self.commands[data["name"]])
            ctx.content = content
            ctx._state = self.bot.http
            parsed_ctx = await self.bot.get_context(ctx)
            ctx.view = parsed_ctx.view
            ctx.args, ctx.kwargs = parsed_ctx.args, parsed_ctx.kwargs
            for name in dir(parsed_ctx):
                if not name.startswith(
                    (
                        "__", "send", "reply", "trigger", "typing", "created",
                        "channel", "message", "guild"
                    )
                ):
                    setattr(ctx, name, getattr(parsed_ctx, name))

            await self.bot.invoke(ctx.message)
            try:
                await wait_for(ctx.replied.wait(), timeout=8)
            except AioTimeoutError:
                return ("Error", "Timeout")
            else:
                assert ctx.replied_content is not None
                return ("Ok", ctx.replied_content)
        except Exception as e:
            if ctx:
                self.bot.dispatch("command_error", ctx, e)
            return ("Error", str(e))


def setup(bot):
    bot.add_cog(SettingManager(bot))
