# rtutil - Converters

from discord.ext import commands


class Multiple(commands.Converter):

    converter = commands.MemberConverter

    async def convert(self, ctx: commands.Context, arg: str):
        return [await self.converter().convert(ctx, word) for word in arg.split(", ")]


class Members(Multiple):
    ...


class TextChannels(Multiple):
    converter = commands.TextChannelConverter


class VoiceChannels(Multiple):
    converter = commands.VoiceChannelConverter


class Roles(Multiple):
    converter = commands.RoleConverter
