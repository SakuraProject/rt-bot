# Free RT Util - Views

import discord
import platform

class TimeoutView(discord.ui.View):
    "タイムアウト時にコンポーネントを使用不可に編集するようにするViewです。"

    if platform.python_version_tuple()[0]=='3' and int(platform.python_version_tuple()[1])>9:
        message: discord.Message | None = None
    else:
        message: discord.Message

    async def on_timeout(self):
        for child in self.children:
            if hasattr(child, "disabled"):
                child.disabled = True
        if self.message is not None:
            await self.message.edit(view=self)
