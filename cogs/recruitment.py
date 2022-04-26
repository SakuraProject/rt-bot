# Free RT - Recruitment

from discord.ext import commands, tasks
import discord

from asyncio import create_task
from time import time


class Recruitment(commands.Cog):

    EMOJI = "<:puls:876338285528612895>"

    def __init__(self, bot):
        self.bot, self.queue = bot, {}
        self.worker.start()

    @commands.command(
        extras={
            "headding": {"ja": "募集パネル",
                         "en": "Recruitment Panel"},
            "parent": "ServerPanel"
        },
        aliases=["recruit", "rct"]
    )
    async def recruitment(self, ctx, title, max_: int, deadline: int, *, description=""):
        """!lang ja
        --------
        募集パネルを作ります。

        Parameters
        ----------
        title : str
            募集パネルのタイトルです。  
            タイトルに空白を含める際は`"`で囲んでください。
        max : int
            募集する人数です。
        deadline : int
            締め切りまでの日数です。  
            0にすると無期限となります。
        description : str, optional
            募集パネルの説明です。なくても構いません。

        Examples
        --------
        ```
        rf!recruitment りつちゃんにナンパする人募集します。 3 3
        集合場所：RTサーバー
        希望人材：かっこいい奴
        ```
        [実行結果](http://tasuren.syanari.com/RT/help/ServerPanel/recruitment.jpg)

        Aliases
        -------
        recruit, rct

        !lang en
        --------
        Create a recruitment panel.

        Parameters
        ----------
        title : str
            The title of the recruitment panel.  
            If you want to include space into title, you have to sandwich the title in double quotation marks.
        max : int
            The maximum number of people to recruit.
        deadline : int
            The number of days to set the deadline.  
            0 means no deadline.
        description : str, optional
            Description of the recruitment panel.

        Examples
        --------
        ```
        rf!recruitment "Recruiting people to pick up Ritsu-chan." 3 3
        Meeting place: RT server
        Desired Talent: Cool guys.
        ```
        [Run result](http://tasuren.syanari.com/RT/help/ServerPanel/recruitment.jpg)

        Aliases
        -------
        recruit, rct"""
        embed = discord.Embed(
            title=title,
            description=description if description else discord.Embed.Empty,
            color=ctx.author.color
        )
        embed.add_field(
            name={"ja": "参加者", "en": "Participant"},
            value="今はいません。/ nobody now",
            inline=False
        )
        embed.add_field(
            name={"ja": "最大募集人数", "en": "Max. number of people raised"},
            value=str(max_)
        )
        if deadline:
            deadline = time() + 86400 * deadline
        embed.add_field(
            name={"ja": "締め切り", "en": "Deadline"},
            value=f"<t:{int(deadline)}:R>" if deadline else "なし / None"
        )
        embed.set_footer(
            text={"ja": "※連打防止のため結果の反映には数秒かかります。",
                  "en": "※It will take a few seconds for the results to be reflected to prevent repeated hits."}
        )
        message = await ctx.webhook_send(
            content="RT募集パネル, ID:" + str(deadline),
            username=ctx.author.display_name, avatar_url=ctx.author.avatar.url,
            embed=embed, wait=True
        )
        await message.add_reaction(self.EMOJI)

    async def update_panel(self, payload: discord.RawReactionActionEvent):
        # 募集パネルの更新を行う。
        members, i = "", 0

        # Embedの参加者を作る。
        for reaction in payload.message.reactions:
            if str(reaction.emoji) == self.EMOJI:
                async for member in reaction.users():
                    if not member.bot:
                        i += 1
                        members += f"{member.mention}\n"
                break

        now = time()
        deadline = (now + 10 if payload.embed.fields[2].value == "なし / None"
                    else float(payload.message.content[12:]))
        if int(payload.embed.fields[1].value) >= i and now < deadline:
            embed = payload.embed
            # 最後に改行があるはずなのでそのいらない改行を消す。
            members = members[:-1]
            members = members if members else "今はいません。/ nobody now"

            if members != embed.fields[0].value:
                # Embedを変える必要があるならEmbedを更新する。
                embed.set_field_at(
                    0, name={"ja": "参加者", "en": "Participant"},
                    value=members, inline=False
                )

                webhook = discord.utils.get(
                    await payload.message.channel.webhooks(),
                    name="RT-Tool"
                )
                await webhook.edit_message(payload.message_id, embed=embed)
        else:
            await payload.message.remove_reaction(self.EMOJI, payload.member)

    @tasks.loop(seconds=3.5)
    async def worker(self):
        # キューにある募集パネルの編集を行うためのループです。
        for key in list(self.queue.keys()):
            create_task(self.update_panel(self.queue[key]))
            del self.queue[key]

    @commands.Cog.listener()
    async def on_full_reaction_add(self, payload):
        if (hasattr(payload, "message") and "RT募集パネル" in payload.message.content
                and payload.message.author.bot and payload.message.guild
                and payload.message.embeds and str(payload.emoji) == self.EMOJI
                and not payload.member.bot):
            # キューに追加する。
            payload.emoji, payload.embed = str(payload.emoji), payload.message.embeds[0]

            self.queue[f"{payload.channel_id}.{payload.message_id}"] = payload

    @commands.Cog.listener()
    async def on_full_reaction_remove(self, payload):
        await self.on_full_reaction_add(payload)

    def cog_unload(self):
        self.worker.cancel()


def setup(bot):
    bot.add_cog(Recruitment(bot))
