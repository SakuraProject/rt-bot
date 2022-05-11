# Free RT - WebSockets

from typing import Union

from discord.ext import commands
import discord

from util import RT, websocket


DISCORD = "/img/discord.jpg"


class WebSockets(commands.Cog):
    def __init__(self, bot: RT):
        self.bot = bot

    def convert_channel(
        self, channel: Union[
            discord.TextChannel, discord.VoiceChannel,
            discord.Thread, discord.StageChannel
        ]
    ) -> dict:
        return {
            "id": str(channel.id), "name": channel.name,
            "voice": isinstance(
                channel, (discord.VoiceChannel, discord.StageChannel)
            )
        }

    def convert_channels(self, channels: list) -> dict:
        return [
            self.convert_channel(channel)
            for channel in channels
        ]

    def convert_role(self, role: discord.Role) -> dict:
        return {
            "name": role.name, "id": str(role.id)
        }

    def convert_user(self, user: Union[discord.User, discord.Member]) -> dict:
        return {
            "name": user.name, "id": str(user.id), "icon_url": getattr(
                user.display_avatar, "url", DISCORD
            )
        }

    def convert_guild(self, guild: discord.Guild) -> dict:
        return {
            "name": guild.name, "id": str(guild.id), "icon_url": getattr(
                guild.icon, "url", DISCORD
            ), "text_channels": self.convert_channels(guild.text_channels),
            "voice_channels": self.convert_channels(guild.voice_channels),
            "channels": self.convert_channels(guild.channels),
            "roles": [self.convert_role(role) for role in guild.roles],
            "members": [self.convert_user(member) for member in guild.members]
        }

    @websocket.websocket("/api/guild", auto_connect=True, reconnect=True)
    async def guild(self, ws: websocket.WebSocket, _):
        await ws.send("on_ready")

    @guild.event("on_ready")
    async def on_ready(self, ws: websocket.WebSocket, _):
        await self.guild(ws, None)

    @guild.event("fetch_guilds")
    async def fetch_guilds(self, ws: websocket.WebSocket, user_id: str):
        user_id = int(user_id)
        return [
            self.convert_guild(guild) for guild in self.bot.guilds
            if any(member.id == user_id for member in guild.members)
        ]


async def setup(bot):
    await bot.add_cog(WebSockets(bot))
