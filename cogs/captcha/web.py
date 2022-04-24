# Free RT Captcha - Web Captcha

from typing import TYPE_CHECKING

import discord

from urllib.parse import quote
from reprypt import encrypt

from .image import Select, make_random_string

if TYPE_CHECKING:
    from .__init__ import Captcha


class WebCaptchaView(discord.ui.View):
    def __init__(self, captcha: "WebCaptcha", *args, **kwargs):
        self.captcha, self.characters = captcha, make_random_string(
            captcha.password_length
        )
        self.on_success = captcha.cog.remove_queue
        super().__init__(*args, **kwargs)
        self.add_item(discord.ui.Button(
            label="Go to captcha page | 認証ページに行く",
            emoji="<:hCaptcha:923086020570927114>", url="".join((
                self.captcha.cog.bot.get_website_url(),
                "captcha?session=", quote(encrypt(
                    self.characters, self.captcha.cog.bot.secret["secret"]
                ))
            ))
        ))
        self.add_item(Select(
            self, placeholder="The code in the webpage | ウェブページにあったコード"
        ))

    async def on_failed(self, guild_id: int, user_id: int):
        ...


class WebCaptcha:
    def __init__(self, cog: "Captcha", password_length: int = 5):
        self.cog, self.password_length = cog, password_length
        self.view = discord.ui.View()

    async def on_captcha(self, interaction: discord.Interaction):
        await interaction.response.send_message(
            {"ja": "以下のボタンを押してウェブにある認証ページにてコードを取得してください。\nそしたら取得したコードと同じコードを選んでください。",
             "en": "Click on the button below to get the code on the captcha page on the web.\nThen select the same code as the one you got."},
            view=WebCaptchaView(self, timeout=360), ephemeral=True
        )