# RT - Captcha Web Manager

from typing import TYPE_CHECKING, TypedDict, Dict, Tuple

import discord

from inspect import cleandoc
from time import time

if TYPE_CHECKING:
    from .__init__ import Captcha


class SuccessedUserData(TypedDict):
    guild_id: int
    user_id: int
    channel: discord.TextChannel


class WebCaptcha:
    def __init__(self, captcha_cog: "Captcha", secret: str):
        self.cog = captcha_cog
        self.secret: str = secret
        self.queue: Dict[str, Tuple[int, float, discord.TextChannel]] = {}
        self.base_url = (
            "http://localhost/"
            if self.cog.bot.test
            else "https://rt-bot.com/"
        )

    async def success_user(self, userdata: SuccessedUserData):
        "ユーザーの認証成功時の処理を実行する。"
        if ((guild := self.cog.bot.get_guild(userdata["guild_id"]))
                and (member := guild.get_member(userdata["user_id"]))):
            # 役職などを取得して役職を付与する。
            row = await self.cog.load(userdata["guild_id"])
            role = guild.get_role(row[3])

            if role:
                try:
                    await member.add_roles(role)
                except discord.Forbidden:
                    result = (
                        "認証に失敗しました。"
                        "付与する役職がRTの役職より下にあるか確認してください。\n"
                        "Failed, make sure that the role position below the RT role position.\n"
                    )
                else:
                    result = (
                        "認証に成功しました。"
                        "役職が付与されました。\n"
                        "Success!"
                    )
                    self.cog.remove_cache(member)
                    n = f"{member.guild.id}-{member.id}"
                    if n in self.queue:
                        del self.queue[n]
            else:
                result = (
                    "役職が見つからないので役職を付与できませんでした。"
                    "すみません！！\n"
                    "Ah, I couldn't find the role to add to you."
                )
        else:
            result = (
                "あなたの所在がわからないため認証に失敗しました。"
            )
        await userdata["channel"].send(
            f"<@{userdata['user_id']}>, {result}"
        )

    async def captcha(
        self, channel: discord.TextChannel, member: discord.Member
    ) -> None:
        self.queue[f"{member.guild.id}-{member.id}"] = (member.id, time(), channel)
        embed = discord.Embed(
            title={"ja": "ウェブ認証", "en": "Web Captcha"},
            description={
                "ja": cleandoc("""喋るには認証をしなければいけません。
                    認証を開始するには下にあるボタンから認証ページにアクセスしてください。
                    ※放置されると無効になります。"""),
                "en": cleandoc("""You must do authentication to speak.
                    Please access to that url to do authentication.
                    * If you leave it, it will become invalid.""")
            }, color=self.cog.bot.colors["normal"]
        )
        embed.set_footer(
            text="Powered by hCaptcha", icon_url="https://www.google.com/s2/favicons?domain=hcaptcha.com"
        )
        view = discord.ui.View()
        view.add_item(discord.ui.Button(label="認証を行う", url=f"{self.base_url}captcha"))
        await channel.send(
            member.mention, embed=embed, view=view, target=member.id
        )
