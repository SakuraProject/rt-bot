# Free RT - Old Role Panel

from typing import Callable, Coroutine, Optional, Dict

from discord.ext import commands, tasks
import discord

from emoji import UNICODE_EMOJI_ENGLISH
from asyncio import create_task


class OldRolePanel(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.emojis = [chr(0x1f1e6 + i) for i in range(26)]
        self.queue: Dict[str, discord.RawReactionActionEvent] = {}
        self.worker.start()

    def make_embed(
        self, title: str, emojis: dict, color: discord.Color
    ) -> discord.Embed:
        "役職パネル用のEmbedを作ります。"
        return discord.Embed(
            title=title,
            description="\n".join(
                f"{emoji} {emojis[emoji]}"
                for emoji in emojis
            ), color=color
        )

    @commands.command(
        extras={"headding": {
            "ja": "古い方式で役職パネルを作成します。",
            "en": "Create a position panel using the old method."
        }, "parent": "ServerPanel"}
    )
    @commands.has_permissions(administrator=True)
    async def oldrole(self, ctx, title, *, content):
        """!lang ja
        --------
        リアクション方式の役職パネルを作成します。  
        古いやり方なため`role`の方を使うのを強く推奨します。  
        使い方はその新しい`role`と同じです。  
        ※役職の個数制限機能はこの古い役職パネルだと使えません。
        
        Parameters
        ----------
        title: タイトル
            役職パネルのタイトルです。
        content: 役職名(メンション)を1行ずつ区切って入力
            役職パネルでつけ外しをすることができる役職の一覧です。  
            1行に1つの役職名(もしくはメンション)を入れてください。  
            また、役職名の前に絵文字を入れることでその絵文字で反応するようにさせることができます。

        See Also
        --------
        role : モダンな役職パネル

        !lang en
        --------
        Creates a reaction-based position panel.  
        It is strongly recommended to use the `role` one, as it is the old way.  
        The usage is the same as the new `role`.  
        The `role` panel is the same as the new one.

        See Also
        --------
        role : New role panel"""
        emojis = self.parse_description(content, ctx.guild)
        if emojis:
            embed = self.make_embed(title, emojis, ctx.author.color)
            embed.set_footer(
                text={
                    "ja": "※連打防止のため役職の付与は数秒遅れます。",
                    "en": "※There will be a delay of a few seconds in granting the position to prevent consecutive hits."
                }
            )

            message = await ctx.webhook_send(
                "RT役職パネル", embed=embed, username=ctx.author.display_name,
                avatar_url=getattr(ctx.author.avatar, "url", ""), wait=True
            )
            await message.add_reaction("🛠")
            for emoji in emojis:
                await message.add_reaction(emoji)
        else:
            raise commands.CommandError(
                {"ja": "何も役職を指定されていないため役職パネルを作れません。",
                 "en": "I can't make the role panel because nothing role."}
            )

    async def update_role(
        self, payload: discord.RawReactionActionEvent, emojis: Dict[str, str] = None
    ) -> None:
        """役職の付与剥奪を行う。
        Embedから絵文字とメンションを取り出す。"""
        if emojis is None:
            emojis = self.parse_description(
                payload.message.embeds[0].description, payload.message.guild
            )
        key = str(payload.emoji)
        if key not in emojis:
            key = "<a" + key[1:]
        # 無駄な空白を消すためにsplitする。
        emojis[key] = emojis[key].split()[0]
        role = payload.message.guild.get_role(
            int(emojis[key][3:-1])
        )

        if role:
            # 役職が存在するならリアクションの付与と剥奪をする。
            try:
                if payload.event_type == "REACTION_ADD":
                    await payload.member.add_roles(role)
                elif payload.event_type == "REACTION_REMOVE":
                    await payload.member.remove_roles(role)
            except discord.Forbidden:
                await payload.member.send(
                    "役職の付与に失敗しました。\nサーバー管理者に以下のサイトを見るように伝えてください。\n" \
                    "https://rt-team.github.io/trouble/role"
                )

            del role
        else:
            try:
                await payload.member.send(
                    "".join(f"{payload.message.guild.name}での役職の付与に失敗しました。",
                            "\n付与する役職を見つけることができませんでした。"))
            except Exception as e:
                print(e)

    def parse_description(
        self, content: str, guild: discord.Guild, make_default: bool = True
    ) -> Dict[str, Optional[str]]:
        "文字列の行にある絵文字とその横にある文字列を取り出す関数です。"
        i, emojis, result = -1, [], {}
        for line in content.splitlines():
            if line and line != "\n":
                i += 1
                not_mention: bool = "@" not in line

                if line[0] == "<" and all(char in line for char in (">", ":")):
                    if not_mention or line.count(">") != 1:
                        # もし外部絵文字なら。
                        emojis.append(line[:line.find(">") + 1])
                elif line[0] in UNICODE_EMOJI_ENGLISH or line[0] in self.emojis:
                    # もし普通の絵文字なら。
                    emojis.append(line[0])
                elif make_default:
                    # もし絵文字がないのなら作る。
                    emojis.append(self.emojis[i])
                    line = self.emojis[i] + " " + line
                else:
                    emojis.append(None)

                result[emojis[-1]] = line.replace(emojis[-1], "")

                # もし取り出した役職名の最初が空白なら空白を削除する。
                if result[emojis[-1]][0] in (" ", "　"):
                    result[emojis[-1]] = result[emojis[-1]][1:]
                # もしメンションじゃないならメンションに変える。
                if not_mention:
                    role = discord.utils.get(guild.roles, name=result[emojis[-1]])
                    if role is None:
                        raise commands.RoleNotFound(
                            f"{result[emojis[-1]]}という役職が見つかりませんでした。"
                        )
                    else:
                        result[emojis[-1]] = role.mention

        return result

    def cog_unload(self):
        self.worker.cancel()

    @tasks.loop(seconds=4)
    async def worker(self):
        # キューにあるpayloadをupdate_roleに渡して役職の付与剥奪をする。
        # 連打された際に毎回役職を付与剥奪しないように。
        for cmid in list(self.queue.keys()):
            create_task(self.update_role(self.queue[cmid]))
            del self.queue[cmid]

    def check(self, payload: discord.RawReactionActionEvent) -> bool:
        "役職パネルかチェックする。"
        return (payload.message.embeds and payload.message.author.bot
                and payload.message.content == "RT役職パネル" and payload.message.guild
                and any(str(payload.emoji) == str(reaction.emoji)
                        or getattr(payload.emoji, "name", "") == \
                            getattr(reaction.emoji, "name", "fdslafsjkfjskaj")
                        for reaction in payload.message.reactions))

    async def send_template(
        self, payload: discord.RawReactionActionEvent,
        send: Optional[Callable[..., Coroutine]] = None,
        extend: Callable[[str, discord.RawReactionActionEvent], str] \
            = lambda c, _: c, **kwargs
    ) -> None:
        await (send or payload.member.send)(
            content=extend(
                f"rf!role {payload.message.embeds[0].title}\n" + "\n".join(
                    (e + " " + getattr(
                        payload.message.guild.get_role(
                            int(m.split()[0][3:-1])
                        ), "name", "役職が見つかりませんでした。")
                    ) for e, m in self.parse_description(
                        payload.message.embeds[0].description,
                        payload.message.guild
                    ).items()
                ), payload
            ), **kwargs
        )

    @commands.Cog.listener()
    async def on_full_reaction_add(self, payload: discord.RawReactionActionEvent):
        if self.bot.is_ready() and hasattr(payload, "message"):
            if self.check(payload) and not payload.member.bot:
                emoji = str(payload.emoji)
                # もしテンプレートの取得ならテンプレートを返す。
                if payload.event_type == "REACTION_ADD":
                    if emoji == "🛠":
                        return await self.send_template(payload)
                if emoji in payload.message.embeds[0].description:
                    # キューに追加する。
                    i = f"{payload.channel_id}.{payload.message_id}.{payload.member.id}"
                    i += "." + emoji
                    self.queue[i] = payload
                else:
                    await payload.message.remove_reaction(emoji, payload.member)

    @commands.Cog.listener()
    async def on_full_reaction_remove(self, payload: discord.RawReactionActionEvent):
        if str(payload.emoji) != "🛠":
            await self.on_full_reaction_add(payload)


def setup(bot):
    bot.add_cog(OldRolePanel(bot))
