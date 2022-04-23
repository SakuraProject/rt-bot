# Free RT - Server Tool

from typing import Union

from datetime import datetime, timedelta
from asyncio import TimeoutError, sleep
from random import sample

from discord.ext import commands
import discord

from util.page import EmbedPage
from data import PERMISSION_TEXTS



STAR_HELP = {
    "ja": (
        "スターボード機能",
        "☆のリアクションをつけると`rt>star`がトピックにあるチャンネルにスターがついたメッセージとして送信されます。"
    ),
    "en": (
        "Star board",
        "When you give a ☆ reaction, it will be sent as a starred message to the channel with `rt>star` in the topic."
    )
}


class ServerTool(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.trash_queue = []
        self.bot.loop.create_task(self.on_ready())

    async def on_ready(self):
        await sleep(1.3)
        for lang in STAR_HELP:
            self.bot.cogs["DocHelp"].add_help(
                "ChannelPlugin", "rt>star", lang,
                *STAR_HELP[lang]
            )

    @commands.command(
        aliases=["perm", "権限", "perms", "permissions", "けんげん"], extras={
            "headding": {
                "ja": "指定したユーザーの権限を表示します。",
                "en": "Displays the permissions of the specified user."
            }, "parent": "ServerTool"
        }
    )
    async def permission(
        self, ctx: commands.Context,
        member: Union[discord.Member, discord.Role, str] = None
    ):
        """!lang ja
        -------
        指定されたユーザーの持っている権限を表示します。

        Parameters
        ----------
        member : メンバーのメンションか名前または役職の名前またはメンション
            対象のメンバーか役職の名前/メンションです。

        Aliases
        -------
        perm, perms, 権限, けんげん

        !lang en
        --------
        Displays the permissions of the specified user.

        Parameters
        ----------
        member : Member mention or name
            Target member mention or name.

        Aliases
        -------
        perm, perms"""
        if member is None:
            member = ctx.author
        if isinstance(member, str) and "everyone" in member:
            member = ctx.guild.default_role
        permissions = getattr(
            member, "guild_permissions", getattr(
                member, "permissions", None
            )
        )

        if permissions is None:
            await ctx.reply("見つかりませんでした。")
        else:
            await ctx.reply(
                embed=discord.Embed(
                    title={
                        "ja": "権限一覧", "en": "Permissions"
                    },
                    description="\n".join(
                        (f"<:check_mark:885714065106808864> {PERMISSION_TEXTS[name]}"
                         if getattr(permissions, name, False)
                         else f"<:error:878914351338246165> {PERMISSION_TEXTS[name]}")
                        for name in PERMISSION_TEXTS
                    ), color=self.bot.colors["normal"]
                )
            )

    @commands.command(
        aliases=["serverinfo", "si"], extras={
            "headding": {
                "ja": "サーバーの情報を表示します。",
                "en": "Show server info."
            }, "parent": "ServerUseful"
        }
    )
    async def sinfo(self, ctx, guild_id: int = None):
        """!lang ja
        --------
        サーバーの情報を表示します。

        Parameters
        ----------
        guild_id : int, optional
            対象のサーバーのIDです。  
            指定しなかった場合はコマンドを実行したサーバーとなります。  
            RTのいるサーバーしかサーバー指定はできません。

        Aliases
        -------
        si

        !lang en
        --------
        Show you server info.

        Parameters
        ----------
        guild_id : int, optional
            The ID of the target server.  
            If it is not specified, it is the server where the command was executed.  
            Only the server where RT is located can be specified as the server.

        Aliases
        -------
        si"""
        if guild_id is None:
            guild = ctx.guild
        else:
            guild = self.bot.get_guild(guild_id)
            if guild is None:
                return await ctx.reply(
                    {"ja": "サーバーが見つかりませんでした。",
                     "en": "The server is not found."}
                )

        e = discord.Embed(title=f"{guild.name}の情報",
                          description="", color=0x00ff00)
        e.add_field(name="サーバー名(ID)", value=f"{guild.name}({guild.id})")
        chs = (len(guild.channels), len(guild.categories),
               len(guild.text_channels), len(guild.voice_channels))
        e.add_field(name="チャンネル数",
                    value="%s個(カテゴリ：%s個,テキスト：%s個,ボイス：%s個)" % chs)
        mbs = (len(guild.members),
               len([m for m in guild.members if not m.bot]),
               len([m for m in guild.members if m.bot]))
        e.add_field(name="メンバー数",
                    value="%s人(ユーザー：%s人,Bot：%s人)" % mbs)
        e.add_field(name="作成日時(UTC)", value=guild.created_at)
        e.set_thumbnail(url=guild.icon.url)

        await ctx.reply(embed=e)

    @commands.command(
        aliases=["timem", "tm", "たいむましん", "タイムマシン",
                 "バックトゥザフューチャー", "BackToTheFuture"],
        extras={
            "headding": {
                "ja": "過去のメッセージを表示します。",
                "en": "Displays past messages."
            }, "parent": "Individual"
        }
    )
    async def timemachine(self, ctx, day: int = 1):
        """!lang ja
        --------
        タイムマシン機能です。  
        チャンネルを指定した日数分さかのぼったときのメッセージの内容とメッセージリンクを表示します。

        Parameters
        ----------
        day : int, default 1
            さかのぼる日数です。

        !lang en
        --------
        Time machine.  
        Displays the contents of messages and message links from the specified number of days ago.

        Parameters
        ----------
        day : int, default 1
            It is how many days ago the message should be.

        Aliases
        -------
        timem, tm, たいむましん, タイムマシン, バックトゥザフューチャー"""
        await ctx.trigger_typing()

        if 0 < day:
            try:
                async for message in ctx.channel.history(
                        limit=1, before=datetime.now() - timedelta(days=day)
                    ):
                    e = discord.Embed(
                        description=f"{message.content}\n[メッセージに行く]({message.jump_url})",
                        color=self.bot.colors["normal"]
                    )
                    e.set_author(
                        name=message.author.display_name,
                        icon_url=getattr(message.author.avatar, "url", "")
                    )
                    e.set_footer(text=f"{day}日前のメッセージ | タイムマシン機能")
                    await ctx.reply(embed=e)
                    break
                else:
                    raise OverflowError("さかのぼりすぎた。")
            except (OverflowError, discord.HTTPException):
                await ctx.reply(
                    {"ja": "過去にさかのぼりすぎました。",
                    "en": "I was transported back in time to another dimension."}
                )
        else:
            await ctx.reply(
                {"ja": "未来にはいけません。",
                 "en": "I can't read messages that on the future."}
            )

    def old_easy_embed(
            self, content: str,
            color: discord.Color = discord.Embed.Empty
        ):
        es = ">>"
        spl = content.splitlines()
        title = spl[0][len(es):]
        desc, fields = [], {}

        footer = spl[-1][2:] if ';;' in spl[-1] else None
        if footer:
            spl.pop(-1)

        spl.pop(0)
        f = None
        for c in spl:
            if c == "":
                continue
            if c[0] == '<':
                f = c[1:] if '!' != c[1] else c[2:]
                fields[f] = {'i': True if '!' != c[1] else False, 'c': []}
                continue
            if f:
                fields[f]['c'].append(c)
                continue
            desc.append(c)

        e = discord.Embed(
            title=title,
            description='\n'.join(desc),
            color=color
        )
        for f in fields.keys():
            e.add_field(
                name=f,
                value='\n'.join(fields[f]['c']),
                inline=fields[f]['i']
            )
        if footer:
            e.set_footer(text=footer)

        return e


    @commands.command(
        aliases=["抽選", "choice", "lot"], extras={
            "headding": {
                "ja": "抽選をします。", "en": ""
            }, "parent": "ServerTool"
        }
    )
    async def lottery(
        self, ctx, count: int, *,
        obj: Union[discord.Role, discord.TextChannel] = None,
        target=None
    ):
        """!lang ja
        --------
        指定された人数抽選をします。

        Parameters
        ----------
        count : int
            当たり数です。
        role : 役職かチャンネルのメンションか名前, optional
            抽選に参加するために持っていなければならない役職です。  
            指定しなくても構いません。  
            また、チャンネルのメンションか名前を入れた場合はそのチャンネルを見ることができる人が条件となります。

        Examples
        --------
        `rf!lottery 3 メンバー`
        メンバーの中から三人抽選します。

        !lang en
        --------
        Draws lots for the specified number of people.

        Parameters
        ----------
        count : int
            The number of hits.
        role : mention or position of the position, optional
            This is the role that must be held by the person who will be selected by lottery.  
            You don't need to select it.  
            Also, if it's a channel mention or name, it's someone who can see that channel."""
        if target is None:
            target = ctx.guild.members
            if obj:
                if isinstance(obj, discord.Role):
                    target = [
                        member for member in target
                        if member.get_role(obj.id)
                    ]
                else:
                    target = obj.members

        try:
            embed = discord.Embed(
                title="抽選" if not ctx.message.embeds \
                    else f"{ctx.message.embeds[0].title} - 抽選",
                description=", ".join(
                    member.mention
                    for member in sample(
                        set(filter(lambda m: not m.bot, target)), count
                    )
                ), color=self.bot.colors["normal"]
            )
        except ValueError:
            await ctx.reply("対象のユーザーの人数が指定された数より少ないです。")
        else:
            await ctx.reply(embed=embed)

    @commands.command(
        aliases=[
            "sm", "プレイ((", "スローモード", "すろーもーど",
            "cdn", "クールダウン", "くーるぽこ", "くーるだうん"
        ], extras={
            "headding": {
                "ja": "スローモードを設定します。",
                "en": "Setting slow mode"
            }, "parent": "ServerTool"
        }
    )
    @commands.has_permissions(manage_channels=True)
    @commands.cooldown(1, 300, commands.BucketType.channel)
    async def slowmode(self, ctx, t: int):
        """!lang ja
        --------
        チャンネルにスローモードを設定します。  
        細かい単位でスローモードで設定したい際に使えます。

        Parameters
        ----------
        time : int
            スローモードを何秒で設定するかです。  
            0.5秒などの端数は指定できません。

        Examples
        --------
        `rf!slowmode 2`

        Aliases
        -------
        sm, プレイ((, スローモード, すろーもーど, cdn, くーるだうん, くーるぽこ, クールダウン

        !lang en
        --------
        Sets the channel to slow mode.  
        This can be used when you want to set one second or so in slow mode.

        Parameters
        ----------
        time : int
            Sets the number of seconds to set the slow mode.

        Examples
        --------
        `rf!slowmode 2`.

        Aliases
        -------
        sm"""
        await ctx.trigger_typing()
        await ctx.channel.edit(slowmode_delay=t)
        await ctx.reply("Ok")

    @commands.command(
        aliases=["えっc", "安全じゃない", "だいじょばない", "っていう曲好き"],
        extras={
            "headding": {
                "ja": "iOSユーザーのためのNSFWチャンネル設定コマンド",
                "en": "Setting nsfw channel for iOS user."
            }, "parent": "ServerTool"
        }
    )
    @commands.has_permissions(manage_channels=True)
    @commands.cooldown(1, 300, commands.BucketType.channel)
    async def nsfw(self, ctx):
        """!lang ja
        --------
        実行したチャンネルのNSFWの設定をするまたは解除をします。  
        iOSでNSFWの設定ができないのでそのiOSユーザーのためのコマンドです。  
        実行した時にNSFWに設定されていない場合はNSFWに設定して、NSFWに設定されている場合はNSFWを解除します。

        Aliases
        -------
        えっち, 安全じゃない, だいじょばない, っていう曲好き

        !lang en
        --------
        Set or unset nsfw for the channel you run. 
        This command is for those iOS users who cannot set NSFW on iOS. 
        It sets the channel to nsfw if it is not set to nsfw when executed, and unset nsfw if it is set to nsfw."""
        if hasattr(ctx.channel, "topic"):
            await ctx.trigger_typing()
            await ctx.channel.edit(nsfw=not ctx.channel.nsfw)
            await ctx.reply("Ok")
        else:
            await ctx.reply(
                {"ja": "スレッドにNSFWは設定できません。",
                 "en": "I can't set NSFW to the thread."}
            )

    @commands.command(
        extras={
            "headding": {
                "ja": "招待ランキング",
                "en": "Invite checker."
            }, "parent": "ServerUseful"
        }
    )
    async def invites(self, ctx):
        """!lang ja
        --------
        招待ランキングを表示します。

        !lang en
        --------
        Show you invite ranking."""
        await ctx.reply(
            embed=discord.Embed(
                title=f"{ctx.guild.name}の招待(招待数)ランキング",
                description='\n'.join(
                    a + '：`' + c + "`"
                        for a, c in sorted(
                            [(i.inviter.mention + '(' + i.code + ')',
                              str(i.uses))
                             for i in await ctx.guild.invites()],
                            reverse=True,
                            key=lambda p: int(p[1])
                        )
                    ),
                color=self.bot.colors["normal"]
            )
        )

    @commands.command(
        aliases=["delmes", "削除", "rm", "さくじょ"], extras={
            "headding": {
                "ja": "メッセージ削除コマンド、リアクションメッセージ削除",
                "en": "Delete message command, Delete message by reaction."
            }, "parent": "ServerTool"
        }
    )
    @commands.has_permissions(manage_messages=True)
    @commands.cooldown(1, 10, commands.BucketType.channel)
    async def purge(self, ctx, count: int, target: discord.Member = None):
        """!lang ja
        --------
        メッセージ一括コマンドです。  
        リアクションによるメッセージ削除の説明は一番下にあります。

        Parameters
        ----------
        count : int
            削除するメッセージの数です。
        target : メンバーのメンションまたは名前, optional
            削除するメッセージの送信者を指定します。  
            選択しない場合は送信者関係なくメッセージを削除します。

        Examples
        --------
        `rf!purge 10`

        Notes
        -----
        削除できるメッセージの数は一回に200までです。

        Aliases
        -------
        delmes, rm, 削除, さくじょ

        Notes
        -----
        リアクションによる範囲指定でのメッセージ削除も可能です。  
        やり方は🗑️のリアクションを削除したい複数のメッセージの一番下にまず付けます。  
        そして削除したいメッセージの一番上に同じように🗑️のリアクションをつけます。  
        これだけでできます。[使用例動画](https://youtu.be/cGnnUbVceR8)

        !lang en
        --------
        This is a message batch command.  
        The explanation of message deletion by reaction is at the bottom.

        Parameters
        ----------
        count : int
            The number of messages to delete.
        target : member's mention or name, optional
            Specify the sender of the message to be deleted.  
            If not selected, the message will be deleted regardless of the sender.

        Examples
        --------
        `rf!purge 10`.

        Notes
        -----
        You can only delete up to 200 at a time.

        Aliases
        -------
        delmes, rm

        Notes
        -----
        It is possible to delete a message by specifying a range of reactions.  
        To do this, first put a 🗑️ reaction at the bottom of the messages you want to delete.  
        Then put the same 🗑️ reaction at the top of the message you want to delete.  
        This is the only way to do it. [Example Video](https://youtu.be/cGnnUbVceR8)"""
        await ctx.trigger_typing()
        await ctx.message.delete()
        await ctx.channel.purge(
            limit=200 if count > 200 else count,
            check=lambda mes: target is None or mes.author.id == target.id,
            bulk=True
        )
        await ctx.send("Ok", delete_after=3)

    EMOJIS = {
        "star": ("⭐", "🌟"),
        "trash": "🗑️"
    }

    @commands.Cog.listener()
    async def on_full_reaction_add(self, payload):
        if (not payload.guild_id or not payload.member or payload.member.bot
                or not hasattr(payload, "message")
                or (getattr(payload.message.channel, "topic", "")
                and "rt>star" in payload.message.channel.topic)):
            return

        if (emoji := str(payload.emoji)) in self.EMOJIS["star"]:
            # スターボード
            count = 0
            for reaction in payload.message.reactions:
                if str(reaction.emoji) in self.EMOJIS["star"]:
                    async for user in reaction.users():
                        # もしRTがスターをつけてるなら既にスターボードに乗っているのでやめる。
                        if user.id == self.bot.user.id: return
                        else: count += 1
            else:
                if (channel := discord.utils.find(
                    lambda ch: ch.topic and "rt>star" in ch.topic,
                    payload.message.guild.text_channels
                )):
                    cache = channel.topic[channel.topic.find("rt>star")+7:]
                    try: require = int(cache if (index := cache.find("\n")) == -1 else cache[:index])
                    except ValueError: require = 1
                    if count < require: return
                    embeds = []
                    embeds.append(
                        discord.Embed(
                            title="スターがついたメッセージ",
                            description=payload.message.content,
                            color=0xf2f2b0
                        ).set_author(
                            name=payload.message.author.display_name,
                            icon_url=payload.message.author.avatar.url
                        )
                    )
                    for i, attachment in enumerate(payload.message.attachments):
                        try:
                            embeds[i]
                        except IndexError:
                            embeds.append(discord.Embed())
                        finally:
                            embeds[i].set_image(url=attachment.url)
                    if payload.message.embeds:
                        embeds.extend(payload.message.embeds)
                    if embeds:
                        await channel.send(content=payload.message.jump_url, embeds=embeds)
                        # スターボードにすでにあることを次スターがついた際にわかるようにスターを付けておく。
                        await payload.message.add_reaction(self.EMOJIS["star"][0])

        if (emoji == self.EMOJIS["trash"] and payload.channel_id not in self.trash_queue
                and payload.member.guild_permissions.manage_messages):
            # リアクションメッセージ削除
            self.trash_queue.append(payload.channel_id)
            try:
                new_payload = await self.bot.wait_for(
                    "full_reaction_add", timeout=45.0,
                    check=lambda new_payload: (
                        new_payload.member.id == payload.member.id
                        and new_payload.guild_id == payload.guild_id
                        and str(new_payload.emoji) == emoji
                    )
                )
            except TimeoutError:
                return
            else:
                await payload.message.channel.purge(
                    before=payload.message, after=new_payload.message, bulk=True,
                    limit=200
                )
                await payload.message.delete()
                await new_payload.message.delete()
            finally:
                self.trash_queue.remove(payload.channel_id)

    @commands.command(
        aliases=["メンバー一覧", "メンバー", "mems"], extras={
            "headding": {
                "ja": "ｻｰﾊﾞｰ、ﾁｬﾝﾈﾙ閲覧可能、ﾛｰﾙ所持のﾒﾝﾊﾞｰの一覧を表示します。",
                "en": "Displays a list of members who are on the server, can view channels, and have roles."
            }, "parent": "ServerTool"
        }
    )
    @commands.cooldown(1, 7, commands.BucketType.user)
    async def members(
        self, ctx, *, channel: Union[
            discord.Role, discord.TextChannel,
            discord.VoiceChannel, discord.Thread
        ] = None
    ):
        """!lang ja
        --------
        サーバーにいる人、チャンネルを見れる人または特定の役職を持っている人のメンションと名前とIDを列挙します。

        Parameters
        ----------
        channel : 役職かチャンネルのメンションかIDまたは名前, optinal
            メンバー一覧を見たい対象の役職またはチャンネルです。  
            選択しなかった場合はサーバー全体が対象となります。  
            同じ名前のチャンネルやロールが複数ある場合、ロール->テキストチャンネル->ボイスチャンネル->スレッドの順に優先されます。

        Examples
        --------
        `rf!members 雑談`
        雑談というロールを持っている人またはチャンネルを見れる人の名前を列挙します。

        Aliases
        -------
        mems, メンバー, メンバー一覧

        !lang en
        --------
        Lists mentions, names, and IDs of people who are on the server, have access to the channel, or have a specific role.

        Parameters
        ----------
        channel : Mention, ID or name of the role or channel, optinal
            The role or channel for which you want to see the member list.  
            If not selected, the entire server will be included.

        Examples
        --------
        `rf!members chit chat`
        List the names of people who have the role "chat" or who can see the channel."""
        members = channel.members if channel else ctx.guild.members
        if members:
            # メンバーが多すぎる場合は表示しきれないのでそれぞれ2000文字以下のメンション文字列の二次元配列にする。
            new, i = [], 0
            for member in members:
                for _ in range(2):
                    try:
                        new[i]
                    except IndexError:
                        new.append([])
                    finally:
                        new[i].append(
                            f"{member.mention} {'<:bot:876337342116429844>' if member.bot else ''}\n　{member.name} ({member.id})"
                        )
                        if sum(map(len, new[i])) <= 2000:
                            break
                        else:
                            i += 1

            embeds = [
                discord.Embed(
                    title="メンバー一覧",
                    description="・" + "\n・".join(members),
                    color=self.bot.colors["normal"]
                ) for members in new
            ]
            kwargs = dict(
                embed=embeds[0], view=EmbedPage(data=embeds)
            )
            if i == 0:
                del kwargs["view"]

            await ctx.reply(**kwargs)
        else:
            await ctx.reply(
                "そのチャンネルでは誰もしゃべれません。"
            )


def setup(bot):
    bot.add_cog(ServerTool(bot))
