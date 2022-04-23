# RT Captcha - Word

from typing import TYPE_CHECKING

import discord

if TYPE_CHECKING:
    from .__init__ import Captcha


class WordCaptcha:
    def __init__(self, cog: "Captcha"):
        self.cog = cog

    async def on_message(self, message: discord.Message):
        if message.channel.id == self.cog.queue[message.guild.id] \
                [message.author.id][2].extras["data"]["channel_id"]:
            if message.content == self.cog.queue[message.guild.id] \
                    [message.author.id][2].extras["data"]["word"]:
                await message.delete()
                role = message.guild.get_role(
                    self.cog.queue[message.guild.id][message.author.id][2].role_id
                )
                if role:
                    try:
                        await message.author.add_roles(role)
                    except discord.Forbidden:
                        await message.channel.send(
                            f"{message.author.mention}, 役職を権限がないため付与できませんでした。"
                        )
                    else:
                        await message.channel.send(f"{message.author.mention}, 認証に成功しました。")
                        await self.cog.remove_queue(message.guild.id, message.author.id)
                else:
                    await message.channel.send(
                        f"{message.author.mention}, 付与する役職が見つかりませんでした。"
                    )
            else:
                await message.reply("合言葉が違います。")

    async def on_member_join(self, member: discord.Member):
        if (channel := member.guild.get_channel(
            self.cog.queue[member.guild.id][member.id][2]
                .extras["data"]["channel_id"]
        )):
            await channel.send(f"{member.mention}, 合言葉を送信してください。")