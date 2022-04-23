
from discord.ext import commands


class OnFullReactionAddRemove(commands.Cog):
    def __init__(self, bot, timeout: float = 0.025):
        self.bot, self.timeout = bot, timeout

    @commands.Cog.listener()
    async def on_raw_reaction_add(self, payload):
        await self.on_raw_reaction_addremove(payload, "add")

    @commands.Cog.listener()
    async def on_raw_reaction_remove(self, payload):
        await self.on_raw_reaction_addremove(payload, "remove")

    async def on_raw_reaction_addremove(self, payload, event: str):
        # もし`self.on_reaction_addremove`が呼ばれなかった場合は自分でmessageを取得する。
        try:
            channel = (
                self.bot.get_channel(payload.channel_id)
                if payload.guild_id
                else self.bot.get_user(payload.user_id)
            )
            payload.message = await channel.fetch_message(payload.message_id)
            payload.member = (
                payload.message.guild.get_member(
                payload.user_id)
                if payload.guild_id else None
            )
        except Exception:
            return
        finally:
            # `on_full_reaction_add/remove`を呼び出す。
            self.bot.dispatch("full_reaction_" + event, payload)


def setup(bot):
    timeout = getattr(bot, "_util_ofr_timeout", 0.025)
    bot.add_cog(OnFullReactionAddRemove(bot, timeout=timeout))
