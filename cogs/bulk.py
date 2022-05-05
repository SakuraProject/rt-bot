# Free RT - Bulk

from typing import Union, Literal, List

from discord.ext import commands
import discord


GuildRole = Union[discord.Role, Literal["everyone"]]
Mode = Literal["add", "remove"]


class Bulk(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    def add_error_field(
        self, embed: discord.Embed, failed_members: List[discord.Member], t: str
    ) -> discord.Embed:
        # ここのtには`送信`とかが入る。
        embed.add_field(
            name={"ja": f"{t}に失敗したメンバー一覧",
                  "en": f"List of members who failed {t}"},
            value=("\n".join(f"{member.mention}\n　{e}" for member, e in failed_members)
                   if failed_members else {
                       "ja": f"{t}に失敗したメンバーはいません。",
                       "en": f"No member has failed {t}."}))
        return embed

    @commands.group(
        extras={
            "headding": {
                "ja": "一括で指定した役職またはサーバーメンバー全員にメッセージを送信や役職の付与/剥奪ができます。",
                "en": "Adds or removes the specified role or sends the specified message to specific members who is on this server."
            },
            "parent": "ServerTool"
        }
    )
    @commands.cooldown(1, 60, commands.BucketType.guild)
    @commands.max_concurrency(1, commands.BucketType.guild)
    @commands.has_guild_permissions(administrator=True)
    async def bulk(self, ctx):
        """!lang ja
        --------
        一括でメンバー全員へ役職の付与やメッセージの送信ができます。

        !lang en
        --------
        It can send a message and add a role for some members.
        """
        if not ctx.invoked_subcommand:
            await ctx.reply("使用方法が違います。")

    BULK_HELP = ("ServerTool", "bulk")

    @bulk.command(
        extras={
            "headding": {
                "ja": "一括でメッセージを送信します。", "en": "Send messages in bulk."
            }
        }
    )
    async def send(self, ctx, target: GuildRole, *, content):
        """!lang ja
        --------
        指定されたメッセージを実行したサーバーにいる指定したメンバーに送信します。

        Parameters
        ----------
        target : everyoneまたは役職の名前かメンション
            送る相手です。  
            もしeveryoneならサーバーにいる人全員です。  
            役職の名前かメンションにすればその役職を持っている人のみにメッセージが送信されます。
        content : str
            送る内容です。

        Examples
        --------
        ```
        rf!bulk send @ゲーマー **来月開催する予定のゲーム大会について**
        このゲーム大会では以下のゲームのスコアを競います。
        * MinecraftのPvP
        * Apex
        * スターフォックス64
        * パノラマコットン
        ```

        !lang en
        --------
        Sends the specified message to specific members who is on this server.

        Parameters
        ----------
        target : everyone or the role's name(mention)
            The target to send the message.
            `everyone` sends to all the members in the server.
            A role's name(mention) sends to only members who has the role.

        Examples
        --------
        ```
        rf!bulk send @Gamer **About the tournament of the games in next month**
        You will compete with these score:
        * Minecraft(PvP)
        * Apex
        * Fortnite
        * Super smash bros Special
        ```
        """
        await ctx.typing()

        failed_members = []
        sent_count = 0

        for member in ctx.guild.members:
            if member.id != ctx.author.id and not member.bot:
                # もし送信対象が役職でmemberが役職を持っていないならcontinueする。
                if isinstance(target, discord.Role):
                    if member.get_role(target.id) is None:
                        continue

                try:
                    e = discord.Embed(description=content)
                    e.set_author(name=ctx.author, icon_url=ctx.author.avatar.url)
                    e.set_footer(text="RT一括送信 対象：" + ("全員" if isinstance(target, str) else f"{target.name}を持つ人"))
                    await member.send(embed=e)
                    sent_count += 1
                except (discord.HTTPException, discord.Forbidden):
                    failed_members.append(
                        (member, "権限不足またはメンバーがDMを許可していません。"))
                except Exception as e:
                    failed_members.append(
                        (member, f"何らかの理由で送れませんでした。`{e}`"))

        embed = discord.Embed(
            title={
                "ja": f"{sent_count}人へのメッセージ一括送信が完了しました。",
                "en": f"It has completed to send the message to {sent_count} members collectively."
            },
            color=self.bot.colors["normal"]
        )
        embed = self.add_error_field(embed, failed_members, "送信")
        await ctx.reply(embed=embed)

    @bulk.group()
    async def role(self, ctx):
        """!lang ja
        --------
        ロールの一括系コマンドのグループです。

        !lang en
        --------
        This is the batch system command group for roles."""

    @role.command(
        extras={
            "headding": {
                "ja": "一括で役職の権限を全て設定または解除します。",
                "en": "Sets or removes all permissions of a role in a batch."
            }
        }
    )
    async def edit(self, ctx, mode: Mode, *, role: discord.Role):
        """!lang ja
        --------
        指定された役職に全ての権限を付与または削除します。

        Parameters
        ----------
        mode : add または remove
            addにした場合は全ての権限を付与してremoveの場合は剥奪をします。
        role : ロールの名前またはメンション
            対象のロールです。

        !lang en
        --------
        Grants or removes all privileges for the specified position.

        Parameters
        ----------
        mode : add or remove
            If "add" is selected, all privileges will be granted, and if "remove" is selected, all privileges will be revoked.
        role : Name or Mention of the role
            The target role."""
        await ctx.typing()
        await role.edit(
            permissions=getattr(
                discord.Permissions, "all" if mode == "add" else "none"
            )()
        )
        await ctx.reply("Ok")

    @role.command(
        extras={
            "headding": {
                "ja": "一括で役職の付与/剥奪を行います。",
                "en": "Add/remove role in batches."
            }
        }
    )
    async def manage(self, ctx, mode: Mode, target: GuildRole, *, role: discord.Role):
        """!lang ja
        --------
        実行したサーバーにいる指定したメンバーに指定された役職を付与または剥奪をします。

        Parameters
        ----------
        mode : add または remove
            付与か剥奪どっちを実行するかで、addにすると役職の付与でremoveにすると役職の剥奪となります。
        target : everyoneまたは役職の名前かメンション
            役職の付与または剥奪を行う対象者です。  
            everyoneにした場合はサーバーにいる人全員となります。  
            役職の名前かメンションを入れた場合はその役職を持っている人が対象となります。
        role : 役職名または役職メンション
            付与または剥奪する役職です。

        !lang en
        --------
        Adds or Removes the specified role to specific members who is on this server.

        Parameters
        ----------
        mode : add or remove
            Add or Remove the role literally.
        target : everyone or the role's name(mention)
            The target to send the message.
            `everyone` adds/removes to all the members in the server.
            A role's name(mention) adds/removes to only members who has the role.
        role : Role's name or mention
            A role witch adds or removes.
        """
        await ctx.typing()

        failed_members = []

        for member in ctx.guild.members:
            if not member.bot:
                # もし対象者が特定の役職を持っている人でその役職をmemberが持ってないならcontinueする。
                if isinstance(target, discord.Role):
                    if member.get_role(target.id) is None:
                        continue
                try:
                    if mode == "add":
                        await member.add_roles(role)
                    else:
                        await member.remove_roles(role)
                except (discord.Forbidden, discord.HTTPException):
                    failed_members.append(
                        (member, "権限が足りないかなんかでできませんでした。")
                    )
                except Exception as e:
                    failed_members.append(
                        (member, f"なんらかの原因でできませんでした。`{e}`")
                    )

        embed = discord.Embed(
            title={"ja": "役職付与/剥奪の一括送信が完了しました。", "en": "It has completed to add/remove a role to the members collectively."},
            color=self.bot.colors["normal"]
        )
        embed = self.add_error_field(embed, failed_members, "役職の付与/剥奪")
        await ctx.reply(embed=embed)


async def setup(bot):
    await bot.add_cog(Bulk(bot))
