# Free RT Util - Old features

from typing import Optional, Union, Tuple, List

from discord.ext import commands, tasks  # type: ignore
import discord

from pymysql.err import OperationalError
from . import isintable

# from .slash import Context as SlashContext
from .ext import componesy
from .webhooks import webhook_send
from .cacher import CacherPool


def role2obj(guild: discord.Guild, arg: str) -> list[Optional[discord.Role]]:
    "`役職1, 役職2, ...`のようになってるものをロールオブジェクトに変換します。"
    roles_raw, roles = arg.split(','), []
    for role in roles_raw:
        if '@' in role:
            roles.append(guild.get_role(int(role[3:-1])))
        elif isintable(role):
            roles.append(guild.get_role(int(role)))
        else:
            roles.append(discord.utils.get(guild.roles, name=role))
    return roles


class Roler(commands.Converter):
    "`role2obj`のコンバーターです。現在は非推奨です。util.RolesConverterを使ってください。"
    async def convert(self, ctx, arg):
        return role2obj(ctx.guild, arg)


class FakeMessageForCleanContent:
    def __init__(
        self, guild: Optional[discord.Guild], content: str
    ):
        self.guild, self.content = guild, content
        self.mentions = self._get("member", "")
        self.role_mentions, self.channel_mentions = \
            self._get("role"), self._get("channel")

    def _get(self, get_mode, mentions_mode=None):
        return [
            getattr(self.guild, f"get_{get_mode}")(mention)
            for mention in getattr(
                self, f"raw_{f'{get_mode}_' if mentions_mode is None else mentions_mode}mentions"
            )
        ]


for name in ("clean_content", "raw_mentions", "raw_role_mentions", "raw_channel_mentions"):
    setattr(FakeMessageForCleanContent, name, getattr(discord.Message, name))


def clean_content(content: str, guild: discord.Guild) -> str:
    "渡された文字列を綺麗にします。"
    return FakeMessageForCleanContent(guild, content).clean_content


Context = Union[commands.Context]


# webhook_sendを新しく定義する。
discord.abc.Messageable.webhook_send = webhook_send  # type: ignore
discord.ext.easy = componesy  # type: ignore


def lib_setup(bot, only: Union[Tuple[str, ...], List[str]] = []):
    "元rtlibにあるエクステンションを全てまたは指定されたものだけ読み込みます。"
    for name in ("on_send", "on_full_reaction", "on_cog_add"):
        if name in only or only == []:
            try:
                bot.load_extension("util.ext." + name)
            except commands.ExtensionAlreadyLoaded:
                pass
    for name in ("dochelp", "rtws", "websocket", "debug", "settings", "lib_data_manager"):
        if name in only or only == []:
            try:
                bot.load_extension("util." + name)
            except commands.ExtensionAlreadyLoaded:
                pass
    bot.cachers = CacherPool()


# discord.ext.tasksのタスクがデータベースの操作失敗によって止まることがないようにする。
def tasks_extend():
    if not getattr(tasks.Loop, "_util_extended", False):
        default = tasks.Loop.__init__

        def _init(self, *args, **kwargs):
            default(self, *args, **kwargs)
            self.add_exception_type(OperationalError)
            self.add_exception_type(discord.DiscordServerError)
        tasks.Loop.__init__ = _init
        tasks.Loop._util_extended = True


def sendKwargs(ctx, **kwargs):
    if isinstance(ctx, commands.Context):
        for key in list(kwargs.keys()):
            if (key not in discord.abc.Messageable.send.__annotations__
                    and key in discord.InteractionResponse.send_message.__annotations__):
                del kwargs[key]
    return kwargs
