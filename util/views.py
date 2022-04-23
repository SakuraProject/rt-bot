# RT Util - Views

import discord


class TimeoutView(discord.ui.View):
    "タイムアウト時にコンポーネントを使用不可に編集するようにするViewです。"

    message: discord.Message

    async def timeout(self):
        for child in self.children:
            if hasattr(child, "disabled"):
                child.disabled = True
        await self.message.edit(view=self)
