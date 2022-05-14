# Free RT Util - Views

from typing import Optional

import discord


class TimeoutView(discord.ui.View):
    "タイムアウト時にコンポーネントを使用不可に編集するようにするViewです。"

    message: Optional[discord.Message] = None

    async def on_timeout(self):
        for child in self.children:
            if hasattr(child, "disabled"):
                child.disabled = True
        if self.message is not None:
            await self.message.edit(view=self)
