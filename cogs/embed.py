# Free RT - Embed

from typing import Union

from urllib.parse import quote

from discord.ext import commands
import discord

from util.markdowns import create_embed
from util import RT


class Embed(commands.Cog):
    def __init__(self, bot: RT):
        self.bot = bot

    @commands.group(
        aliases=["埋め込み"], extras={
            "headding": {
                "ja": "埋め込みメッセージを作成します。",
                "en": "Make embed message."
            }, "parent": "ServerUseful"
        }
    )
    async def embed(self, ctx):
        """!lang ja
        -------
        [こちらをご覧ください。](https://rt-team.github.io/ja/notes/embed)

        !lang en
        --------
        Let's see [here](https://rt-team.github.io/en/notes/embed)."""
        if not ctx.invoked_subcommand:
            await ctx.reply("使用方法が違います。")

    @embed.command(aliases=["u", "リンク", "link"])
    async def url(self, ctx: commands.Context, color: Union[discord.Color, str], *, content):
        try:
            e = create_embed(
                f"# {content}", color=ctx.author.color if color == "null" else color
            )
        except TypeError:
            return await ctx.reply(
                {"ja": "色の指定がおかしいです。",
                 "en": "Bad color argument."}
            )
        data = {"color": str(hex(e.color.value))[2:]}
        if e.title:
            data["title"] = e.title
        if e.description:
            data["description"] = e.description
        if ctx.message.attachments:
            data["image"] = ctx.message.attachments[0].proxy_url

        await ctx.reply(
            f"https://rt-bot.com/embed?{'&'.join(f'{name}={quote(value)}' for name, value in data.items())}"
        )

    @embed.command(aliases=["wh", "ウェブフック"])
    @commands.cooldown(1, 10, commands.BucketType.channel)
    async def webhook(
        self, ctx: commands.Context, color: Union[discord.Color, str], *, content
    ):
        rt = False
        if "--rticon" in content:
            content = content.replace(
                " --rticon ", ""
            ).replace(
                " --rticon", ""
            ).replace("--rticon", "")
            rt = True

        try:
            kwargs = {
                "username": ctx.author.display_name,
                "avatar_url": getattr(ctx.author.avatar, "url", ""),
                "embed": create_embed(
                    "# " + content,
                    color=ctx.author.color if color == "null" else color
                )
            }
        except TypeError:
            await ctx.reply(
                {"ja": "色の指定がおかしいです。",
                 "en": "Bad color argument."}
            )
        else:
            if ctx.message.reference:
                message = await ctx.channel.fetch_message(
                    ctx.message.reference.message_id
                )
                kwargs = {"embed": kwargs["embed"]}
                if message.author.id == self.bot.user.id:
                    send = message.edit
                else:
                    wb = discord.utils.get(
                        await message.channel.webhooks(),
                        name="R2-Tool" if self.bot.test else "RT-Tool"
                    )
                    return await wb.edit_message(
                        message.id, **kwargs
                    )
            else:
                send = ctx.channel.webhook_send
                if rt:
                    kwargs = {"embed": kwargs["embed"]}
                    send = ctx.send

            await send(**kwargs)


def setup(bot):
    bot.add_cog(Embed(bot))
