# Free RT Utils - Converters

from discord.ext import commands


class Multiple(commands.Converter):
    "`, `で区切って_originalでconvertしたlistを返すConverterの抽象クラスです。"

    _original: commands.Converter = None  # type: ignore

    async def convert(self, ctx: commands.Context, arg: str):
        return [await self._original().convert(ctx, word) for word in arg.split(", ")]


class MembersConverter(Multiple):
    _original = commands.MemberConverter


class UsersConverter(Multiple):
    _original = commands.UserConverter


class TextChannelsConverter(Multiple):
    _original = commands.TextChannelConverter


class VoiceChannelsConverter(Multiple):
    _original = commands.VoiceChannelConverter


class RolesConverter(Multiple):
    _original = commands.RoleConverter

