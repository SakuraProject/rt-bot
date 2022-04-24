# Free RT - Q&A

from discord.ext import commands
import discord
import datetime

class q_and_a(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command(name="Q&A")
    async def q_and_a(self, ctx):
        for user in self.bot.users:
            if await self.bot.is_owner(user):
                if ctx.author.id == user.id:
                    embed = discord.Embed(
                        title="Free RTのQ&A",
                        description="1️⃣: Free-RT-Botを入れられない\n\n2️⃣: その他の質問\n\n> **上記以外**\n<#962648434316296224>でtiketを立てて質問してください。",
                        color=0x0066FF,
                    )
                    embed.set_footer(text="2022年4月24日 午後3時43分")
                    msg = await ctx.send(embed=embed)
                    await msg.add_reaction("1️⃣")
                    await msg.add_reaction("2️⃣")
                else:
                    await ctx.send("あなたは実行できません。")

    @commands.Cog.listener()
    async def on_raw_reaction_add(self, payload):
        if not payload.user_id == 961521106227974174:
            if payload.channel_id == 967554887833509968:
                if payload.emoji.name == "1️⃣":
                    logchannel = self.bot.get_channel(967556039933304842)
                    await logchannel.send(f"> <@{payload.user_id}>が1️⃣リアクションをつけました。\n{datetime.datetime.utcnow()}(UTC)")
                    channel = self.bot.get_channel(967554887833509968)
                    msg = await channel.send(
                        "botが認証されていないせいです。(ボットマークの横に:white_check_mark:がつく状態)\n今は100サーバー以上にbotを入れることができなくなっている状態です。\n申し訳ありませんが認証までお待ちください。"
                    )
                    await asyncio.sleep(5)
                    await msg.delete()
                if payload.emoji.name == "2️⃣":
                    logchannel2 = self.bot.get_channel(967556039933304842)
                    await logchannel2.send(f"> <@{payload.user_id}>が2️⃣リアクションをつけました。\n{datetime.datetime.utcnow()}(UTC)")
                    channel2 = self.bot.get_channel(967556131377545237)
                    await channel2.send(f"<@{payload.user_id}>さんは質問があるみたいです。")


def setup(bot):
    return bot.add_cog(q_and_a(bot))
