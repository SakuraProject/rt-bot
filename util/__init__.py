# RT Utilities

import discord

from .bot import RT
from .cacher import Cache, Cacher, CacherPool
from .checks import isintable, has_any_roles, has_all_roles
from .converters import (
    MembersConverter,
    UsersConverter,
    TextChannelsConverter,
    VoiceChannelsConverter,
    RolesConverter
)
from .data_manager import DatabaseManager
from .lib_data_manager import Table
from .minesweeper import MineSweeper
from . import mysql_manager as mysql
from .olds import tasks_extend, sendKwargs
from .page import EmbedPage
from .types import sendableString
from .views import TimeoutView
from .webhooks import get_webhook, webhook_send

from .ext import view as componesy

if discord.__title__ == "nextcord":
    from .olds import lib_setup as setup
    from .slash import Context as SlashContext
else:
    from ._dpy_monky import _setup as setup


__all__ = [
    "RT",
    "isintable",
    "has_any_roles",
    "has_all_roles",
    "MembersConverter",
    "UsersConverter",
    "TextChannelsConverter",
    "VoiceChannelsConverter",
    "RolesConverter",
    "DatabaseManager",
    "debug",
    "dochelp",
    "docperser",
    "Table",
    "markdowns",
    "MineSweeper",
    "mysql",
    "olds",
    "tasks_extend",
    "sendKwargs",
    "setup",
    "EmbedPage",
    "rtws",
    "securl",
    "settings"
    "slash",
    "sendableString",
    "TimeoutView",
    "get_webhook",
    "webhook_send",
    "websocket",
    "ext",
    "componesy"
]
