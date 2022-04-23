# Free RT - Role Panel

from __future__ import annotations

from typing import TYPE_CHECKING, Callable, Literal, Union
from types import SimpleNamespace

from collections import defaultdict
from inspect import cleandoc
from time import time

from discord.ext import commands
import discord

from util import get_webhook
from util import RT

if TYPE_CHECKING:
    from ._oldrole import OldRolePanel


get_ja: Callable[[str], str] = \
    lambda mode: "付与" if mode is True or mode == "Add" else "剥奪"
Mode = Literal["Add", "Remove"]


class RoleSelect(discord.ui.Select):

    CUSTOM_ID = "RoleSelectView"
    view: "RoleSelectView"

    async def callback(self, interaction: discord.Interaction):
        # 役職の付与または剥奪を行う。
        is_add = self.custom_id.endswith("Add")
        faileds = []
        for role_id in map(int, self.values):
            if role := interaction.guild.get_role(int(role_id)):
                has = bool(interaction.user.get_role(role.id))
                try:
                    if has and not is_add:
                        await interaction.user.remove_roles(role)
                    elif not has and is_add:
                        await interaction.user.add_roles(role)
                except discord.Forbidden:
                    pass
                else:
                    continue
            faileds.append(role_id)

        self.view.cog.release(interaction.guild_id, interaction.user.id)

        # 付与または削除に失敗した役職があるのならそれのメッセージを作る。
        word = get_ja(is_add)
        faileds = "\n".join(f"・<@&{role_id}>" for role_id in faileds)
        faileds = "".join((
            f"\nですが以下のロールの{word}に失敗しました。\n",
            "RTに権限があるかそして役職が存在しているかを確認してください。\n",
            faileds
        )) if faileds else ""

        await interaction.response.edit_message(
            content={
                "ja": f"役職の{word}をしました。{faileds}",
                "en": cleandoc(
                    f"""{word}ed role(s).
                    However, some of the roles failed to be 
                    {word.lower()}ed.
                    {faileds}"""
                )}, view=None
        )


class RoleSelectView(discord.ui.View):
    def __init__(
        self, guild_id: int, user_id: int, options: list[discord.SelectOption],
        max_: Union[int, None], mode: Mode, cog: "RolePanel",
        *args, **kwargs
    ):
        self.cog, self.user_id, self.guild_id = cog, user_id, guild_id
        length = len(options)
        if max_ is None or length < max_:
            max_ = length
        assert 1 <= length <= 25, "選択項目数がおかしいです。"
        del length
        kwargs["timeout"] = kwargs.get("timeout", 60)
        super().__init__(*args, **kwargs)
        self.add_item(RoleSelect(
            custom_id=f"{RoleSelect.CUSTOM_ID}{mode}", placeholder=f"Role Selector",
            max_values=max_, options=options
        ))
        self.cog.acquire(self.guild_id, self.user_id)

    async def on_timeout(self):
        self.cog.release(self.guild_id, self.user_id)


get_max: Callable[[str], int] = lambda text: int(text[:text.find("個")])
"最大何個までの何個かを取得します。"


class RolePanelView(discord.ui.View):

    CUSTOM_ID = "RolePanelView"

    def __init__(self, cog: "RolePanel", *args, **kwargs):
        self.cog = cog
        kwargs["timeout"] = None
        super().__init__(*args, **kwargs)

    async def process_member(
        self, interaction: discord.Interaction, mode: Mode
    ) -> None:
        if self.cog.is_running(interaction.guild_id, interaction.user.id):
            return await interaction.response.send_message(
                {"ja": "現在別で追加または削除が行われているのでロールの操作ができません。" \
                    "\nもし別の追加または削除を行った際のメッセージを消してしまった場合は一分待ってください。",
                 "en": "The role cannot be manipulated because it is currently being added or deleted separately." 
                    "\nIf you have deleted a message when you added or deleted another one, please wait a minute."},
                ephemeral=True
            )

        if ("複数" not in interaction.message.embeds[0].footer.text
                and mode == "Add"):
            # もし一つしか付与できないモードならまだ何も役職を持っていないことを確認する。
            max_ = get_max(interaction.message.embeds[0].footer.text)
            if max_ <= sum(
                str(role.id) in interaction.message.embeds[0].description
                for role in interaction.user.roles
            ):
                return await interaction.response.send_message(
                    {"ja": cleandoc(f"""この役職パネルは{max_}個までしか役職を手に入れることができません。
                        なので既につけている役職を削除してください。"""),
                     "en": cleandoc(f"""You can only get a maximum of {max_} positions in this role panel.
                        So please delete the roles you already have.""")},
                    ephemeral=True
                )
        else:
            max_ = None

        try:
            await interaction.response.send_message(
                {
                    "ja": f"一分以内に{get_ja(mode)}してほしいロールを選択をしてください。",
                    "en": f"Please select role within a minute."
                }, view=RoleSelectView(
                    interaction.guild_id, interaction.user.id, [
                        discord.SelectOption(
                            label=getattr(
                                interaction.guild.get_role(int(role_id)),
                                "name", role_id
                            ), value=role_id, emoji=emoji
                        ) for emoji, role_id in map(
                            lambda row: (row[0], row[1].split()[0][3:-1]),
                            self.cog.old.parse_description(
                                interaction.message.embeds[0].description,
                                interaction.guild
                            ).items()
                        ) if self.check(
                            mode, int(role_id), interaction.user
                        )
                    ], max_, mode, self.cog
                ), ephemeral=True
            )
        except AssertionError:
            await interaction.response.send_message(
                {"ja": f"{get_ja(mode)}するロールがもうありません。",
                 "en": f"There are no more roles to {mode.lower()}."},
                ephemeral=True
            )

    @staticmethod
    def check(mode: Mode, role_id: int, member: discord.Member) -> bool:
        return (
            not (has := bool(member.get_role(role_id))) and mode == "Add"
        ) or (has and mode == "Remove")

    @discord.ui.button(
        custom_id=f"{CUSTOM_ID}Add", label="Add",
        style=discord.ButtonStyle.success, emoji="➕"
    )
    async def add(self, _, interaction):
        await self.process_member(interaction, "Add")

    @discord.ui.button(
        custom_id=f"{CUSTOM_ID}Remove", label="Remove",
        style=discord.ButtonStyle.danger, emoji="➖"
    )
    async def remove(self, _, interaction):
        await self.process_member(interaction, "Remove")

    def add_only(self, content: str, payload: discord.RawReactionActionEvent) -> str:
        if (isinstance(payload.message.embeds[0].footer.text, str)
                and "複数" not in payload.message.embeds[0].footer.text):
            index = content.find("\n")
            return f"{content[:index]} --only {get_max(payload.message.embeds[0].footer.text)}{content[index:]}"
        return content

    @discord.ui.button(
        custom_id=f"{CUSTOM_ID}Template", label="Template", emoji="🛠"
    )
    async def template(self, _, interaction: discord.Interaction):
        await self.cog.old.send_template(
            SimpleNamespace(message=interaction.message),
            interaction.response.send_message, self.add_only, ephemeral=True
        )


class RolePanel(commands.Cog):
    def __init__(self, bot: RT):
        self.bot = bot
        self.view = RolePanelView(self)
        self.old: "OldRolePanel" = self.bot.cogs["OldRolePanel"]
        self.bot.add_view(self.view)
        self.running: dict[int, dict[int, float]] = defaultdict(dict)

    @commands.command(
        aliases=["役職パネル", "役職", "r"], extras={
            "headding": {
                "ja": "役職パネル", "en": "Role panel"
            }, "parent": "ServerPanel"
        }
    )
    @commands.cooldown(1, 10, commands.BucketType.channel)
    @commands.has_permissions(manage_roles=True)
    async def role(self, ctx: commands.Context, title, *, content):
        """!lang ja
        --------
        役職パネルを作成します。  
        RTの役職パネルはリアクションではなくボタンとセレクター形式で操作しやすくなっています。

        Parameters
        ----------
        title : str
            役職パネルのタイトルです。  
            空白を含めたい場合は`"`で囲んでください。
        content : 内容
            役職パネルに入れる役職です。  
            改行で一つづつわけて役職のメンションか名前を入れてください。  
            作成される役職パネルにはみやすいように自動で絵文字が付きます。  
            この絵文字を自分で指定したい場合は役職の最初に絵文字を置いてください。  
            また、付与できる最大数を指定したい場合は`--only 個数`をcontentの前に以下のように置いてください。
            ```
            rf!role タイトル --only 個数
            役職1
            役職2
            ...
            ```
            それと一つの役職パネルに入れることができる役職の最大個数は25個です。

        Notes
        -----
        もし前に作った役職パネルを編集したい場合は`Template`ボタンを押すことでその役職パネルを作ったときのコマンドを取得できます。  
        そして前の役職パネルに返信をしてコマンドを実行すればその役職パネルを編集して新しくすることができます。

        Examples
        --------
        通常
        ```
        rf!role やっているプログラミング言語
        Python
        Ruby
        C言語
        C++
        C#
        Rust
        Go
        V言語
        BrainFuck
        F#
        BASIC
        なでしこ
        他
        ```
        個数限定
        (この例では二つまでしか選択できない絵文字をカスタムしている役職パネルです。)
        ```
        rf!role ゲーム担当 --only 2
        ⚔️ 戦闘担当
        ❤️ 回復担当
        🛡️ 防御担当
        ```

        !lang en
        --------
        Create a role panel.  
        RT's role panel is modern, with buttons and selectors instead of reactions.

        Parameters
        ----------
        title : str
            The title of the role panel.  
            If you want to include a blank space, enclose it with `"`.
        content : content
            The title of the role panel.  
            Separate one by one with a new line and put the role's mention or name.  
            The role panel will automatically include an emoticon to make it easier to read.  
            If you want to customize this emoji, put it at the beginning of the role.  
            Also, if you want to customize the maximum number of pieces that can be added, put `--only <max count>` before the content like this
            ```
            rf!role title --only <max count>
            Role 1
            Role 2
            ...
            ```
            And the maximum number of roles that can be in one role panel is 25.

        Notes
        -----
        If you want to edit a previously created role panel, you can click the `Template` button to get the command to create a new role panel.  
        You can then reply to the role panel and run the command to edit it and make it new.

        Examples
        --------
        Normal
        ```
        rf!role "What programming language are you using?"
        Python
        Ruby
        C
        C++
        C#
        Rust
        Go
        V
        BrainFuck
        F#
        BASIC
        なでしこ
        Others
        ```
        Number of persons
        (In this example, it is a role panel with custom emoji that can only be selected up to two.)
        ```
        rf!role "Game Positions" --only 2
        ⚔️ Combatant
        ❤️ Healer
        🛡️ Defender
        ```"""
        first = content[:content.find("\n")]
        only_one = "--only" in first
        if only_one:
            content = content.replace("--only ", "")
            max_ = first.replace("--only ", "")
            del first
            content = content.replace(f"{max_}\n", "")
            max_ = int(max_)
        else:
            max_ = 25

        embed = self.bot.cogs["OldRolePanel"].make_embed(
            title, self.bot.cogs["OldRolePanel"].parse_description(
                content, ctx.guild
            ), ctx.author.color
        )
        if embed.description.count("\n") + 1 <= 25:
            embed.set_footer(text=f"{f'{max_}個まで選択可能' if only_one else '複数選択可能'}")
            kwargs = {
                "content": None, "embed": embed, "view": self.view
            }

            if ctx.message.reference:
                await (
                    await (await get_webhook(
                        ctx.channel, f"R{'2' if self.bot.test else 'T'}-Tool"
                    )).edit_message(ctx.message.reference.message_id, **kwargs)
                ).clear_reactions()
            else:
                await ctx.channel.webhook_send(
                    wait=True, avatar_url=getattr(ctx.author.avatar, "url", ""),
                    username=ctx.author.display_name, **kwargs
                )
        else:
            await ctx.reply(
                {"ja": "25個以上を一つの役職パネルに入れることはできません。",
                 "en": "No more than 25 pieces can be placed in a single role panel."}
            )

    def acquire(self, guild_id: int, user_id: int) -> None:
        if user_id not in self.running[guild_id]:
            self.running[guild_id][user_id] = time() + 60

    def release(self, guild_id: int, user_id: int) -> None:
        if user_id in self.running[guild_id]:
            del self.running[guild_id][user_id]
            if not self.running[guild_id]:
                del self.running[guild_id]

    def is_running(self, guild_id: int, user_id: int) -> bool:
        if user_id in self.running[guild_id]:
            if time() > self.running[guild_id][user_id]:
                self.release(guild_id, user_id)
                return False
            return True
        return False


def setup(bot):
    bot.add_cog(RolePanel(bot))
