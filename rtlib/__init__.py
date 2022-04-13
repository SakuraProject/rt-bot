# Free RT - Lib

from typing import Union, Tuple, List

from discord.ext import commands, tasks  # type: ignore
import discord

from pymysql.err import OperationalError

from .slash import Context as SlashContext
from . import mysql_manager as mysql
from .data_manager import Table
from .ext import componesy
from .typed import RT, sendableString
from .cacher import CacherPool, Cacher, Cache


DatabaseManager = mysql.DatabaseManager
Context = Union[SlashContext, commands.Context]


async def webhook_send(channel, *args, webhook_name: str = "RT-Tool", **kwargs):
    """`channel.send`感覚でウェブフック送信をするための関数です。
    `channel.webhook_send`のように使えます。

    Parameters
    ----------
    *args : tuple
        discord.pyのWebhook.sendに入れる引数です。
    webhook_name : str, defualt "RT-Tool"
        使用するウェブフックの名前です。
        存在しない場合は作成されます。
    **kwargs : dict
        discord.pyのWebhook.sendに入れるキーワード引数です。"""
    if isinstance(channel, commands.Context):
        channel = channel.channel
    wb = (
        wb
        if (wb := discord.utils.get(await channel.webhooks(), name=webhook_name))
        else await channel.create_webhook(name=webhook_name)
    )
    try:
        return await wb.send(*args, **kwargs)
    except discord.InvalidArgument as e:
        if webhook_name == "RT-Tool":
            return await webhook_send(channel, *args, webhook_name="R2-Tool", **kwargs)
        else:
            raise e


# webhook_sendを新しく定義する。
discord.abc.Messageable.webhook_send = webhook_send  # type: ignore
discord.ext.easy = componesy  # type: ignore


def setup(bot, only: Union[Tuple[str, ...], List[str]] = []):
    "rtlibにあるエクステンションを全てまたは指定されたものだけ読み込みます。"
    bot.load_extension("rtlib.data_manager")
    for name in ("on_send", "on_full_reaction", "dochelp", "debug", "on_cog_add"):
        if name in only or only == []:
            try:
                bot.load_extension("rtlib.ext." + name)
            except commands.ExtensionAlreadyLoaded:
                pass
    bot.load_extension("rtlib.websocket")
    bot.load_extension("rtlib.rtws")
    bot.load_extension("rtlib.setting")
    bot.cachers = CacherPool()


# discord.ext.tasksのタスクがデータベースの操作失敗によって止まることがないようにする。
if not getattr(tasks.Loop, "_rtlib_extended", False):
    default = tasks.Loop.__init__

    def _init(self, *args, **kwargs):
        default(self, *args, **kwargs)
        self.add_exception_type(OperationalError)
        self.add_exception_type(discord.DiscordServerError)

    tasks.Loop.__init__ = _init
    tasks.Loop._rtlib_extended = True


def sendKwargs(ctx, **kwargs):
    if isinstance(ctx, commands.Context):
        for key in list(kwargs.keys()):
            if (
                key not in discord.abc.Messageable.send.__annotations__
                and key in discord.InteractionResponse.send_message.__annotations__
            ):
                del kwargs[key]
    return kwargs
