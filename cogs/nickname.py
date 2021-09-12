# RT - Nickname Panel

from discord.ext import commands, tasks
import discord

from emoji import UNICODE_EMOJI_ENGLISH
from typing import Type, Dict


class NicknamePanel(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.emojis = [chr(0x1f1e6 + i) for i in range(26)]
        for e in ("add", "remove"):
            self.bot.add_listener(
                self.on_full_reaction_add_remove,
                f"on_full_reaction_{e}"
            )

    def parse_description(self, description: str) -> Dict[str, str]:
        # 文字列から絵文字と文字列を分けて取り出す。
        data, i, emoji = {}, -1, ""
        for line in description.splitlines():
            i += 1
            if line and line != "\n":
                if line[0] == "<" and all(char in line for char in (">", ":")):
                    if not_mention or line.count(">") != 1:
                        # もし外部絵文字なら。
                        emoji = line[:line.find(">") + 1]
                elif line[0] in UNICODE_EMOJI_ENGLISH or line[0] in self.emojis:
                    # もし普通の絵文字なら。
                    emoji = line[0]
                else:
                    # もし絵文字がないのなら作る。
                    emoji = self.emojis[i]
                    line = self.emojis[i] + line

                data[emoji] = line.replace(emoji, "")
        return data

    @commands.command(
        aliases=["nkp", "ニックネームパネル", "ニックパネル", "にっくぱねる", "nicknamepanel"],
        extras={
            "headding": {
                "ja": "ニックネームパネル", "en": "Nickname Panel"
            }, "parent": "ServerPanel"
        }
    )
    async def nickpanel(self, ctx, *, description):
        """!lang ja
        --------
        ニックネームパネルを作ります。

        Parameters
        ----------
        title : str
            ニックネームパネルのタイトルです。
        description : str
            ニックネームパネルに入れるニックネームです。  
            ニックネームの最初に`+`を置くと名前の後ろに後付けされます。

        Examples
        --------
        ```
        rt!nickpanel 通話中切り替え
        +通話中
        +聞き専通話中
        私は誰
        ```

        Notes
        -----
        リアクションをつけるとニックネームがかわりリアクションを外すと普通の名前になります。"""
        title = description[:(index := description.find("\n"))]
        description = description[index:]
        emojis = self.parse_description(description)
        embed = discord.Embed(
            title=title,
            description="\n".join(
                f"{emoji} {value if value[0] == '+' else '-' + value}"
                for emoji, value in emojis.items() if value
            ),
            color=ctx.author.color
        )
        embed.set_footer(
            text="※連打防止のため反映が遅れることがあります。"
        )
        message = await ctx.channel.webhook_send(
            username=ctx.author.display_name,
            avatar_url=ctx.author.avatar.url if ctx.author.avatar else "",
            content="RT Nickname Panel", embed=embed, wait=True
        )
        for emoji in emojis:
            await message.add_reaction(emoji)

    async def on_full_reaction_add_remove(
        self, payload: discord.RawReactionActionEvent,
    ):
        if (not payload.message.guild or not payload.message.author.bot
                or "RT Nickname Panel" != payload.message.content
                or not payload.message.embeds or payload.member.bot
                or not payload.message.embeds[0].description):
            return

        emojis = self.parse_description(
            payload.message.embeds[0].description
        )
        if (value := emojis.get(str(payload.emoji))):
            nick = (
                (
                    (payload.member.display_name + value.replace("+", "", 1))
                    if "+" in value else value.replace("-", "", 1)
                ) if payload.event_type == "REACTION_ADD"
                else payload.member.name
            )
            if payload.member.nick != nick:
                try:
                    await payload.member.edit(nick=nick)
                except (discord.Forbidden, discord.HTTPException):
                    pass


def setup(bot):
    bot.add_cog(NicknamePanel(bot))