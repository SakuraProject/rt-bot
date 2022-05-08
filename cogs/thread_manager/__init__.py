# Free RT - Thread Manager

from typing import TYPE_CHECKING

from discord.ext import commands
import discord

from asyncio import sleep

from .constants import MAX_CHANNELS, HELP
from .dataclass import DataManager

if TYPE_CHECKING:
    from aiomysql import Pool
    from util import Backend


class ThreadManager(commands.Cog, DataManager):
    def __init__(self, bot: "Backend"):
        self.bot = bot
        self.pool: "Pool" = self.bot.mysql.pool
        self.cache = []
        super(commands.Cog, self).__init__(self)

    async def cog_load(self):
        await self.on_help_reload()

    @commands.group(
        slash_command=True, description="スレッド管理用コマンドです。", extras={
            "headding": {
                "ja": "スレッドマネージャー", "en": "Thread Manager"
            }, "parent": "ServerTool"
        }
    )
    @commands.guild_only()
    @commands.has_permissions(manage_threads=True)
    async def threading(self, ctx: commands.Context):
        """!lang ja
        --------
        スレッドマネージャーです。  
        スラッシュコマンドに対応しています。  
        ヘルプのチャンネルプラグインカテゴリーにはスレッド作成専用チャンネルという似た機能が存在します。  
        そちらも確認してみてください。

        !lang en
        --------
        Thread Manager"""
        if ctx.invoked_subcommand:
            if not hasattr(ctx, "interacton"):
                await ctx.trigger_typing()
        else:
            await ctx.reply(
                {"ja": "使用方法が違います。",
                 "en": "It is used in different ways."}
            )

    @threading.command(
        "list", description="設定されている監視対象チャンネルの一覧を表示します。",
        aliases=["l", "一覧"]
    )
    async def list_(self, ctx: commands.Context):
        """!lang ja
        --------
        スレッドが勝手にアーカイブされないようにRTが監視しているチャンネルの一覧です。

        Aliases
        -------
        l, 一覧

        !lang en
        --------
        This is a list of channels monitored so that threads set to RT are not automatically archived.

        Aliases
        -------
        l"""
        await ctx.reply(
            embed=discord.Embed(
                title={
                    "ja": "スレッド監視対象チャンネル",
                    "en": "Inspection Target Channels"
                }, description="\n".join(
                    f"・<#{channel_id}>"
                    for channel_id in (await self.get_data(ctx.guild.id).get_channels()).keys()
                ), color=self.bot.colors["normal"]
            )
        )

    NOT_CHANNEL = {
        "ja": "チャンネルを指定してください。",
        "en": "Please select channel."
    }

    @threading.command(
        description="指定したチャンネルにあるスレッドがアーカイブされないように監視します。",
        aliases=["watch", "it", "監視", "inspect"]
    )
    async def monitor(
        self, ctx, *, channel: discord.TextChannel
    ):
        """!lang ja
        --------
        指定されたチャンネルのスレッドが勝手に閉じられないように設定します。

        Parameters
        ----------
        channel : テキストチャンネルの名前またはメンション
            自動アーカイブを防止するために監視をする対象のチャンネルです。

        Aliases
        -------
        mon, 監視, it, inspect, watch

        !lang en
        --------
        Prevents the thread of the specified channel from being closed by itself.

        Parameters
        ----------
        channel : Name or Mention of the text channel.
            This is the channel to be monitored to prevent automatic archiving.

        Aliases
        -------
        mon, it, inspect, watch"""
        if isinstance(channel, discord.TextChannel):
            await self.get_data(ctx.guild.id).add_channel(channel.id)
            await ctx.reply("Ok")
        else:
            await ctx.reply(self.NOT_CHANNEL)

    @threading.command(
        description="スレッド監視をしているチャンネルを監視解除します。",
        aliases=["unwatch", "unit", "監視解除", "uninspect"]
    )
    async def unmonitor(
        self, ctx, *, channel: discord.TextChannel
    ):
        """!lang ja
        --------
        スレッドが自動アーカイブされないように監視しているチャンネルの監視を解除するコマンドです。

        Parameters
        ----------
        channel : テキストチャンネルの名前またはメンション
            監視を解除する対象のチャンネルです。

        Aliases
        -------
        unwatch, uninspect, unit, 監視解除

        !lang en
        --------
        This command is used to unmonitor a channel that is being monitored to prevent threads from being automatically archived.

        Parameters
        ----------
        channel : Name or Mention of the text channel
            The channel to be unmonitored.

        Aliases
        -------
        unwatch, uninspect, unit"""
        if isinstance(channel, discord.TextChannel):
            await self.get_data(ctx.guild.id).remove_channel(channel.id)
            await ctx.reply("Ok")
        else:
            await ctx.reply(self.NOT_CHANNEL)

    @threading.command(
        description="このコマンドを実行したスレッドに指定されたユーザーを参加させます。",
        aliases=["add", "追加", "a"]
    )
    async def join(
        self, ctx: commands.Context, *, user: discord.Member
    ):
        """!lang ja
        --------
        このコマンドを実行したスレッドにユーザーを参加させます。

        Parameters
        ----------
        user : メンバーの名前またはメンション
            スレッドに参加させるメンバーです。

        Aliases
        -------
        add, a, 追加

        !lang en
        --------
        This command will join a user to the thread in which it is executed.  
        This will allow you to add other members to the thread without having to do any mentions.

        Parameters
        ----------
        user : Member's name or Mention
            The member to join the thread.

        Aliases
        -------
        add, a"""
        assert isinstance(ctx.channel, discord.Thread), "チャンネルでないといけません。"
        await ctx.channel.add_user(user)
        await ctx.reply("Ok")

    @threading.command(
        description="このコマンドを実行したスレッドから指定されたユーザーをキックします。",
        aliases=["k", "rm", "remove", "キック", "追放"]
    )
    async def kick(
        self, ctx: commands.Context, *, user: discord.Member
    ):
        """!lang ja
        --------
        このコマンドを実行したスレッドから指定したメンバーを退出させます。

        Parameters
        ----------
        user : メンバーの名前またはメンション
            スレッドから退出させるメンバーです。

        Aliases
        -------
        k, rm, remove, キック, 追放

        !lang en
        --------
        Kicks the specified member from the thread where this command was executed.

        Parameters
        ----------
        user : Member's name or Mention
            The member to be kicked from the thread.

        Aliases
        -------
        k, rm, remove"""
        assert isinstance(ctx.channel, discord.Thread), "チャンネルでないといけません。"
        await ctx.channel.remove_user(user)
        await ctx.reply("Ok")

    @threading.group(
        description="スレッドアーカイブ解除と作成通知を設定します。",
        aliases=("nof", "通知")
    )
    async def notification(self, ctx):
        """!lang ja
        --------
        スレッドのアーカイブ解除と作成通知を行います。
        `rt!threading notification`で現在設定されている通知設定を表示します。

        Aliases
        -------
        nof, 通知

        !lang en
        --------
        Thread unarchiving and creation notifications.
        Displays the currently configured notification settings in `rt!threading notification`.

        Aliases
        -------
        nof"""
        if not ctx.invoked_subcommand:
            if self.check_notification_onoff(ctx.guild.id):
                await ctx.reply(embed=discord.Embed(
                    title="スレッド通知",
                    description="\n".join(
                        f"<#{channel_id}>：<@&{role_id}>"
                        for channel_id, role_id in self.notification[ctx.guild.id].channels
                    ), color=self.bot.colors["normal"]
                ))
            else:
                await ctx.reply("まだ設定されていません。 / Not set yet.")

    def prepare_notification(self, ctx):
        if "channels" not in self.notification[ctx.guild.id]:
            self.notification[ctx.guild.id].channels = []

    @notification.command("set", aliases=("s", "設定"))
    async def set_notification(self, ctx, *, role: discord.Role):
        """!lang ja
        --------
        実行したチャンネルにスレッド通知を設定します。

        Parameters
        ----------
        role : ロールのメンションか名前またはID
            通知時にメンションするロール

        Aliases
        -------
        s, 設定

        !lang en
        --------
        Sets thread notification to the executed channel.

        Parameters
        ----------
        role : Mention or name or ID of the role
            Roles to be mented during notification

        Aliases
        -------
        s"""
        self.prepare_notification(ctx)
        assert len(self.notification[ctx.guild.id].channels) < 10, {
            "ja": "これ以上設定できません。", "en": "No further settings are possible."
        }
        self.notification[ctx.guild.id].channels.append((ctx.channel.id, role.id))
        await ctx.reply("Ok")

    @notification.command("delete", aliaes=("del", "rm", "remove", "削除"))
    async def delete_notification(self, ctx):
        """!lang ja
        --------
        実行したチャンネルのスレッド通知設定を解除します。

        Aliases
        -------
        del, remove, rm, 削除

        !lang en
        --------
        Cancels the thread notification setting for the executed channel.

        Aliases
        -------
        del, remove, rm"""
        self.prepare_notification(ctx)
        assert [t for t in self.notification[ctx.guild.id].channels if t[0] == ctx.channel.id], {
            "ja": "設定されていません。", "en": "Not set yet."
        }
        for index, t in enumerate(self.notification[ctx.guild.id].channels):
            if t[0] == ctx.channel.id:
                del self.notification[ctx.guild.id].channels[index]

    @kick.error
    async def on_addkick_error(self, ctx, error):
        if isinstance(error, AssertionError):
            if "チャンネル" in str(error):
                await ctx.reply(
                    {"ja": "スレッドのみこのコマンドを実行できます。",
                     "en": "This command can run only thread."}
                )
            else:
                await ctx.reply(
                    {"ja": "これ以上追加できません。",
                     "en": f"I can't add the channel more than {MAX_CHANNELS}."}
                )
        elif isinstance(error, discord.HTTPException):
            if ctx.command.name == "add":
                await ctx.reply(
                    {"ja": "既にユーザーは追加されています。",
                     "en": "The user is already added."}
                )
            else:
                await ctx.reply(
                    {"ja": "そのユーザーはスレッドにいません。",
                     "en": "The user is not founc from thread."}
                )

    @commands.Cog.listener()
    async def on_thread_update(self, before: discord.Thread, after: discord.Thread):
        if (after.archived and not after.locked
            and after.parent.id in await (
                self.get_data(after.guild.id)).get_channels()):
            # 自動ロックされたならロックを解除する。
            await after.edit(archived=False)
        if (before.archived and not after.archived) or (before.locked and not after.locked):
            # アーカイブ解除時には通知を行う。
            if after.guild.id in self.cache:
                self.cache.remove(after.guild.id)
            else:
                self.cache.append(after.guild.id)
                await self.process_notification(after, "アーカイブ解除通知")
                await sleep(5)
                if after.guild.id in self.cache:
                    self.cache.remove(after.guild.id)

    @commands.Cog.listener()
    async def on_thread_join(self, thread: discord.Thread):
        if discord.utils.get(thread.members, id=self.bot.user.id) is None:
            if thread.guild.id in self.cache:
                self.cache.remove(thread.guild.id)
            else:
                self.cache.append(thread.guild.id)
                await self.process_notification(thread, "スレッド作成通知")
                await sleep(5)
                if thread.guild.id in self.cache:
                    self.cache.remove(thread.guild.id)

    @commands.Cog.listener()
    async def on_help_reload(self):
        await sleep(1.5)
        for lang in HELP:
            self.bot.cogs["DocHelp"].add_help(
                "ChannelPlugin", "ThreadCreationChannel",
                lang, *HELP[lang]
            )

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if (hasattr(message.channel, "topic") and message.channel.topic
                and "rt>thread" in message.channel.topic
                and message.author.id != self.bot.user.id):
            if "rt>thread bot" in message.channel.topic or not message.author.bot:
                # スレッド作成専用チャンネルにメッセージが送信されたならスレッドを作る。
                if message.channel.slowmode_delay < 10:
                    # もしスローモードが設定されていないなら十秒にする。
                    await message.channel.edit(slowmode_delay=10)
                content = message.clean_content

                await message.channel.create_thread(
                    name=(
                        content[:content.find("\n")]
                        if "\n" in content else content
                    ),
                    message=message
                )


async def setup(bot):
    await bot.add_cog(ThreadManager(bot))
