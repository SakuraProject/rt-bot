# RT - Page, Notes: これはパブリックドメインとします。

from __future__ import annotations

from typing import Literal, Optional, Any

import discord

from .views import TimeoutView


class BasePage(TimeoutView):
    def __init__(self, *args, data: Optional[Any] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.data, self.page = data, 0

    async def on_turn(
        self, mode: Literal["dl", "l", "r", "dr"], interaction: discord.Interaction
    ):
        self.page = self.page + \
            (-1 if mode.endswith("l") else 1)*((mode[0] == "d")+1)

    @discord.ui.button(emoji="⏪")
    async def dash_left(self, _, interaction: discord.Interaction):
        await self.on_turn("dl", interaction)

    @discord.ui.button(emoji="◀️")
    async def left(self, _, interaction: discord.Interaction):
        await self.on_turn("l", interaction)

    @discord.ui.button(emoji="▶️")
    async def right(self, _, interaction: discord.Interaction):
        await self.on_turn("r", interaction)

    @discord.ui.button(emoji="⏩")
    async def dash_right(self, _, interaction: discord.Interaction):
        await self.on_turn("dr", interaction)


class EmbedPage(BasePage):
    def __init__(self, *args, data: Optional[list[discord.Embed]] = None, **kwargs):
        assert data is not None, "埋め込みのリストを渡してください。"
        super().__init__(*args, data=data, **kwargs)

    async def on_turn(self, mode: str, interaction: discord.Interaction):
        before = self.page
        await super().on_turn(mode, interaction)
        try:
            assert 0 <= self.page
            embed = self.data[self.page]
        except (AssertionError, IndexError):
            self.page = before
            if mode == "dl":
                self.page = 0
                embed = self.data[self.page]
            elif mode == "dr":
                self.page = len(self.data) - 1
                embed = self.data[self.page]
            else:
                return await interaction.response.send_message(
                    "これ以上ページを捲ることができません。", ephemeral=True
                )
        await interaction.response.edit_message(embed=embed, **self.on_page())

    def on_page(self):
        return {}