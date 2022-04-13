# rtutil

from typing import Optional

from discord.ext import commands
import discord

from .minesweeper import Ms as Minesweeper
from .data_manager import DatabaseManager


def check_int(v: str) -> bool:
    "渡された文字列が整数かどうかをチェックします。"
    try:
        int(v)
    except BaseException:
        return False
    else:
        return True


def similer(before: str, after: str, check_length: int) -> bool:
    "beforeがafterとcheck_lengthの文字数分似ているかどうかをチェックします。"
    return any(
        after[i : i + check_length] in before for i in range(len(after) - check_length)
    )


def has_roles(member: discord.Member, roles: list[discord.Role]) -> bool:
    "メンバーが指定された役職の中にあるかどうかを確かめます。"
    return any(role in member.roles for role in roles)


def role2obj(guild: discord.Guild, arg: str) -> list[Optional[discord.Role]]:
    "`役職1, 役職2, ...`のようになってるものをロールオブジェクトに変換します。"
    roles_raw, roles = arg.split(","), []
    for role in roles_raw:
        if "@" in role:
            roles.append(guild.get_role(int(role[3:-1])))
        elif check_int(role):
            roles.append(guild.get_role(int(role)))
        else:
            roles.append(discord.utils.get(guild.roles, name=role))
    return roles


class Roler(commands.Converter):
    "`role2obj`のコンバーターです。"

    async def convert(self, ctx, arg):
        return role2obj(ctx.guild, arg)


async def get_webhook(
    channel: discord.TextChannel, name: str = "RT-Tool"
) -> Optional[discord.Webhook]:
    "ウェブフックを取得します。"
    return discord.utils.get(await channel.webhooks(), name=name)


class FakeMessageForCleanContent:
    def __init__(self, guild: Optional[discord.Guild], content: str):
        self.guild, self.content = guild, content
        self.mentions = self._get("member", "")
        self.role_mentions, self.channel_mentions = self._get("role"), self._get(
            "channel"
        )

    def _get(self, get_mode, mentions_mode=None):
        return [
            getattr(self.guild, f"get_{get_mode}")(mention)
            for mention in getattr(
                self,
                f"raw_{f'{get_mode}_' if mentions_mode is None else mentions_mode}mentions",
            )
        ]


for name in (
    "clean_content",
    "raw_mentions",
    "raw_role_mentions",
    "raw_channel_mentions",
):
    setattr(FakeMessageForCleanContent, name, getattr(discord.Message, name))


def clean_content(content: str, guild: discord.Guild) -> str:
    "渡された文字列を綺麗にします。"
    return FakeMessageForCleanContent(guild, content).clean_content
