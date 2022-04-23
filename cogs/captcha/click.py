# RT Captcha - Click

from typing import TYPE_CHECKING

from discord import Interaction

from .image import add_roles

if TYPE_CHECKING:
    from .__init__ import Captcha


class ClickCaptcha:
    def __init__(self, cog: "Captcha"):
        self.cog = cog
        self.captcha = self
        self.on_success = self.on_failed

    async def on_captcha(self, interaction: Interaction):
        # クリックするだけの認証方式のため付与するだけ。
        return await add_roles(self, interaction, True)

    async def on_failed(self, guild_id: int, user_id: int):
        ...
