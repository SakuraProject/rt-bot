# Free RT - Poll (Vote)

from typing import Callable, Tuple, List, Dict

from asyncio import create_task

from discord.ext import commands, tasks
import discord

from emoji import UNICODE_EMOJI_ENGLISH

from util import RT


class CloseButton(discord.ui.View):
    def __init__(self, *args, **kwargs):
        self._color = kwargs.pop("color", 0)
        kwargs["timeout"] = None
        super().__init__(*args, **kwargs)

    @discord.ui.button(label="締め切る", custom_id="poll.close", emoji="💾")
    async def close(self, _, interaction: discord.Interaction):
        if str(interaction.user.id) == interaction.message.embeds[0].author.name[3:]:
            emojis = []
            for line in interaction.message.embeds[0].description.splitlines():
                splited = line.split()
                emojis.append(
                    (
                        int(splited[0][1:-1]), splited[1],
                        line.replace(" ".join(splited[:2]), "")
                    )
                )
            embed = discord.Embed(
                title="投票結果", description="投票数順です。",
                color=self._color
            )
            for count, emoji, subject in sorted(
                emojis, key=lambda x: x[0], reverse=True
            ):
                embed.add_field(
                    name=f"{emoji} {subject}", value=str(count), inline=False
                )
            await interaction.response.edit_message(
                content=interaction.message.embeds[0].title,
                view=None, embed=embed
            )
        else:
            await interaction.response.send_message(
                "投票をした人でないと締め切ることはできません。", ephemeral=True
            )


class Poll(commands.Cog):
    def __init__(self, bot: RT):
        self.bot, self.rt = bot, bot.data
        self.emojis = [chr(0x1f1e6 + i) for i in range(26)]
        self.queue: Dict[str, discord.RawReactionActionEvent] = {}
        self.view = CloseButton(color=self.bot.Colors.normal)
        self.bot.add_view(self.view)
        self.panel_updater.start()

    @commands.Cog.listener()
    async def on_message(self, message):
        if message.content.startswith("投票rt "):
            message.content = message.content.replace("投票rt", "rf!poll")
            await self.bot.process_commands(message)

    @commands.command(
        extras={"headding": {"ja": "投票パネルを作成します。", "en": "..."},
                "parent": "ServerPanel"},
        aliases=["vote"]
    )
    @commands.cooldown(1, 8)
    async def poll(self, ctx, title, only_one: bool, *, content):
        """!lang ja
        --------
        投票パネルを作成します。

        Parameters
        ----------
        title : str
            投票パネルのタイトルです。  
            もしタイトルに空白を含める場合は`"`で囲んでください。
        only_one : bool
            これをonにした場合は投票を一人一票までに制限します。  
            一人何票でも投票できるようにする場合はoffを入れてください。
        content : str
            項目を改行で分けて入れます。  
            行の最初に絵文字を置くとその絵文字が投票パネルに使われます。  
            もし絵文字を置かない場合は自動でアルファベットの絵文字が割り振られます。

        Examples
        --------
        ```
        rf!poll 好きな人は？ on
        😊 tasuren
        ミスティックガール
        吹雪ちゃん
        NYN姉貴
        🤭 野獣先輩
        ```
        好きな人を問う投票パネルを一人一票までとして作ります。  
        [実行結果](http://tasuren.syanari.com/RT/help/ServerPanel/poll.jpg)

        !lang en
        --------
        Creates a voting panel.

        Parameters
        ----------
        title : str
            The title of the voting panel.  
            If you want to include spaces in the title, please put double quotation marks between the titles.
        only_one : bool
            If this is turned on, only one vote per person is allowed.  
            If you don't want to allow only one person to vote, turn it off.
        content : str
            This is the item to be included in the poll, separated by a new line.  
            If you put an emoticon at the beginning of the line, the emoticon will be used in the voting panel.  
            If no emoji is placed, an alphabet emoji will be assigned automatically.

        Examples
        --------
        ```
        rf!poll "Who's your favorite?" on
        😊 tasuren
        Mystic Girl
        Hubuki-chan
        NYN sister
        🤭 senior beast
        ```
        Create a voting panel asking who you like, with a limit of one vote per person.  
        [Run result](http://tasuren.syanari.com/RT/help/ServerPanel/poll.jpg)"""
        if content.count("\n") > 25:
            return await ctx.reply(
                {"ja": "項目が多すぎるため投票パネルを作れませんでした。最大25個までです。",
                 "en": "There were too many items to make a voting panel. Up to 25."}
            )
        description, emojis = self.make_description(content)

        embed = discord.Embed(
            title=title,
            description=description,
            color=ctx.author.color
        )
        embed.set_footer(
            text={"ja": "※連打防止のため結果の反映は数秒遅れます。",
                  "en": "The results will be delayed for a few seconds to prevent repeated hits."}
        )
        embed.set_author(name=f"ID:{ctx.author.id}")
        mes = await ctx.webhook_send(
            "".join(("RT投票パネル", " (一人一票)" if only_one else "", "\n📊 [...]")),
            wait=True, view=self.view, embed=embed, username=ctx.author.display_name,
            avatar_url=getattr(ctx.author.avatar, "url", ""),
        )
        for emoji in emojis:
            try:
                await mes.add_reaction(emoji)
            except discord.ext.commands.errors.CommandInvokeError:
                await ctx.reply(
                    {"ja": f"{emoji}が見つかりませんでした。",
                     "en": "..."}
                )

    def make_description(self, content: str, on_integer: Callable = None) -> Tuple[str, List[str]]:
        "渡された情報から投票パネルの説明に入れる文字列を作成する。"
        description, i, emojis, emoji = "", -1, [], ""
        index, did = int(on_integer is not None), False

        for line in content.splitlines():
            if line and line != "\n":
                # もし初期状態の作成時ではないならindexを0じゃないのに変更しておく。
                if index and not did:
                    index = line.find("` ") + 2
                    did = True

                i += 1
                # 絵文をを取り出す。絵文字がないなら絵文字を用意する。
                if line[index] == "<" and ">" in line and line.count(":") > 1:
                    # もし外部絵文なら。
                    emojis.append(line[line.find("<"):line.find(">") + 1])
                elif line[index] in UNICODE_EMOJI_ENGLISH:
                    # もし普通の絵文字なら。
                    emojis.append(line[index])
                elif line[index] == self.emojis[i]:
                    emojis.append(line[index])
                else:
                    # もし絵文字がないなら作る。(ABCの絵文字。)
                    emojis.append((emoji := self.emojis[i]))
                    line = emoji + " " + line

                description += (f"`{0 if on_integer is None else on_integer(emojis[-1])}` "
                                + line[index:] + "\n")
        del content, i, emoji

        return description, emojis

    def check_panel(self, payload: discord.RawReactionActionEvent) -> bool:
        # RTの投票パネルか確認するための関数です。
        return (payload.message.content.startswith("RT投票パネル") and not payload.member.bot
                and payload.message.guild and payload.message.embeds
                and any(str(payload.emoji) == str(reaction.emoji)
                        for reaction in payload.message.reactions))

    def graph(self, p: dict, size: int = 28) -> str:
        "グラフを作るための関数です。"
        r, t = '[', len(p)

        for n in list(p.keys()):
            p[n] = int(p[n] / t * size)
            if p[n] % 2 == 0:
                p[n] += 1

            if p[n] > 1:
                r += '<'
            if p[n] > 3:
                r += '=' * int((p[n] - 3 if p[n] - 3 > 0 else 0) / 2)
            r += n
            if p[n] > 3:
                r += '=' * int((p[n] - 3) / 2)
            if p[n] > 1:
                r += '>'
        return r + ']'

    async def update_panel(self, payload: discord.RawReactionActionEvent):
        # RTの投票パネルをアップデートする。
        embed = payload.message.embeds[0]
        emojis = {str(reaction.emoji): reaction.count - 1
                  for reaction in payload.message.reactions}
        # 最大桁数を数える。
        before = 1
        for key in emojis:
            if before < (now := len(str(emojis[key]))):
                before = now
        # Embedを編集する。

        def _get_emoji(emoji):
            return str({str(reaction.emoji): reaction.count - 1
                        for reaction in payload.message.reactions}
                       [emoji]).zfill(before)
        description, _ = self.make_description(
            embed.description, _get_emoji
        )
        if description != embed.description:
            # もしカウントが変わっているならメッセージを編集する。
            embed.description = description
            wb = discord.utils.get(
                await payload.message.channel.webhooks(), name="RT-Tool"
            )
            if wb:
                try:
                    await wb.edit_message(
                        payload.message_id, embed=embed,
                        content="".join(
                            (payload.message.content[:payload.message.content.find("\n")],
                             "\n📊 ", self.graph(emojis), "")))
                except discord.InvalidArgument:
                    pass
        del description, emojis

    def cog_unload(self):
        self.panel_updater.cancel()

    @tasks.loop(seconds=4)
    async def panel_updater(self):
        # キューにあるpayloadからパネルを更新する。
        # 連打された際に連打全部に対応して編集するようなことが起きないように。
        for cmid in list(self.queue.keys()):
            create_task(self.update_panel(self.queue[cmid]))
            del self.queue[cmid]

    @commands.Cog.listener()
    async def on_full_reaction_add(self, payload: discord.RawReactionActionEvent):
        if self.bot.is_ready() and hasattr(payload, "message"):
            if self.check_panel(payload):
                cmid = f"{payload.channel_id}.{payload.message_id}"
                if payload.event_type == "REACTION_ADD":
                    # もし一人一票までなら投票できるかチェックをする。
                    if "一" in payload.message.content:
                        users = len(
                            [reaction for reaction in payload.message.reactions
                             if any(user.id == payload.member.id
                                    for user in await reaction.users().flatten())]
                        )
                        if users > 1:
                            await payload.message.remove_reaction(
                                payload.emoji, payload.member
                            )
                            return
                self.queue[cmid] = payload

    @commands.Cog.listener()
    async def on_full_reaction_remove(self, payload: discord.RawReactionActionEvent):
        await self.on_full_reaction_add(payload)


def setup(bot):
    bot.add_cog(Poll(bot))
