# Free RT - AutoMod

from typing import Callable, Coroutine, Literal, Union, Any, Dict, Tuple, List

from discord.ext import commands
import discord

from util import RT

from .modutils import process_check_message, trial_new_member, trial_invite
from .data_manager import GuildData, DataManager
from .cache import Cache


def reply(description: str, color: str = "normal", **kwargs) -> dict:
    "埋め込み返信用のkwargsを作ります。"
    return {"title": "AutoMod", "description": description, "color": color, **kwargs}
OK = "Ok"


class AutoMod(commands.Cog, DataManager):

    COLORS = {
        "normal": 0x66b223,
        "warn": 0xDDBB04,
        "error": 0xF288AA
    }

    def __init__(self, bot: RT):
        self.bot = bot
        self.caches: Dict[int, Tuple[GuildData, Dict[int, Cache]]] = {}
        self.enabled: List[int] = []
        super(commands.Cog, self).__init__(self)

    def cog_unload(self):
        self.close()

    def print(self, *args, **kwargs) -> None:
        return self.bot.print("[AutoMod]", *args, **kwargs)

    Sendable = Union[commands.Context, discord.TextChannel]
    async def setting(
        self, function: Callable[..., Coroutine], channel: Sendable, *args, **kwargs
    ) -> discord.Message:
        "何かを設定するコマンドに便利な関数"
        self.print(f"[setting.{function.__name__}]", channel.guild.id)
        args, kwargs = await function(channel, *args, **kwargs)
        return await self.reply(channel, *args, **kwargs)

    async def reply(self, channel: Sendable, *args, **kwargs) -> discord.Message:
        if args:
            args = list(args)
            if args[0] == OK:
                if kwargs.pop("add_or_remove", None):
                    args[0] = "onに設定しました。"
                else:
                    args[0] = "offに設定しました。"
            else:
                kwargs["color"] = "error"
            kwargs["title"] = "AutoMod"
            kwargs["description"] = args[0]
            args = ()
        if kwargs:
            if "color" not in kwargs:
                kwargs["color"] = self.COLORS["normal"]
            elif isinstance(kwargs["color"], str):
                kwargs["color"] = self.COLORS[kwargs["color"]]
            kwargs = {"embed": discord.Embed(**kwargs)}
        if hasattr(channel, "reply"):
            return await channel.reply(*args, **kwargs)
        else:
            return await channel.send(*args, **kwargs)

    @commands.group(
        aliases=["am", "自動モデレーション", "安全"], extras={
            "headding": {
                "ja": "自動モデレーション機能", "en": "Auto Moderation"
            }, "parent": "ServerSafety"
        }
    )
    @commands.guild_only()
    @commands.has_permissions(administrator=True)
    @commands.cooldown(1, 5, commands.BucketType.guild)
    async def automod(self, ctx: commands.Context):
        """!lang ja
        --------
        自動モデレーション機能です。  
        `rf!automod`でこの機能を有効または無効にすることができます。

        Notes
        -----
        管理者権限を持っている人は処罰対象になりません。

        Warnings
        --------
        しっかりとヘルプを読んで設定をしましょう。  
        さもないと痛い目にあいます。

        Aliases
        -------
        am, 安全, 自動モデレーション

        !lang en
        --------
        Auto Moderation

        Notes
        -----
        Administrator will not be punished.  
        You can enable this feature with `rf!automod`.

        Warnings
        --------
        Make sure you read the help file carefully.  
        If you don't, you will get hurt.

        Aliases
        -------
        am"""
        if ctx.invoked_subcommand:
            # もしまだAutoModを有効にしていない状態でこのコマンドのサブコマンドを実行したならエラーを起こす。
            await ctx.trigger_typing()
            assert ctx.guild.id in self.enabled, "このサーバーではAutoModが有効になっていません。" \
                "\n`rf!automod`を実行してください。"
            await self.prepare_cache_guild(ctx.guild)
        else:
            if ctx.message.content.endswith(("automod", "amd", "自動モデレーション")):
                await self.reply(ctx, OK, add_or_remove = await self.toggle_automod(ctx.guild.id))
            else:
                await self.reply(ctx, "使用方法が違います。")

    async def nothing(self, _, *args, **kwargs):
        "settingで何もしたくない時のためのものです。"
        return args, kwargs

    async def ignore_setting(
        self, channel: Sendable, mode: Literal["add", "remove", "toggle"],
        key: str, obj, *args, **kwargs
    ):
        "例外設定のコマンドでのsetting関数の使用ための"
        id_ = getattr(obj, "id", obj)
        try:
            if mode == "add":
                if id_ not in self.caches[channel.guild.id][0][key]:
                    assert len(self.caches[channel.guild.id][0][key]) < 15, "これ以上追加できません。"
                    self.caches[channel.guild.id][0][key].append(id_)
            elif mode == "remove":
                self.caches[channel.guild.id][0][key].remove(id_)
            else:
                if key in self.caches[channel.guild.id][0]:
                    del self.caches[channel.guild.id][0][key]
                else:
                    self.caches[channel.guild.id][0][key] = []
        except KeyError:
            if kwargs.pop("nokeyerror", False):
                self.caches[channel.guild.id][0][key] = []
                return await self.ignore_setting(
                    channel, mode, key, obj, *args, **kwargs
                )
            else:
                return ("この機能は有効になっていません。",), kwargs
        except ValueError:
            return ("その例外は設定されていません。",), kwargs
        else:
            return args, kwargs

    @automod.command("ignore", aliases=["例外", "i"])
    async def ignore_spam(
        self, ctx: commands.Context, mode: Literal["add", "remove", "list"],
        channel: Union[discord.TextChannel, discord.Object] = None
    ):
        """!lang ja
        -------
        spam(高速でメッセージを送信すること)の検知をしない例外チャンネルを設定します。  
        登録したチャンネルでは、spamをしてもRTがなにもしないようになります。  
        spam検知例外チャンネルはNekoBotなどの画像Botのコマンドを使うためのチャンネル等に設定しましょう。  
        また、設定した際はそのチャンネルにスローモードをつけるなど対策を取ることを推奨します。

        Parameters
        ----------
        mode : add または remove または list
            `add`にした場合は指定されたチャンネルをスパム検知をしないチャンネルリストに追加します。  
            `remove`にした場合は指定されたチャンネルをスパム検知をしないチャンネルリストから削除します。  
            `list`にした場合はスパム検知をしないチャンネルリストを表示します。
        channel : テキストチャンネルの名前かメンションまたはID, optional
            追加/削除するチャンネルです。  
            これは`mode`引数を`list`にした場合は省略できます。

        Aliases
        -------
        i, 例外

        !lang en
        --------
        Sets an exception channel for spam detection.  
        In the spam detection exception channel registered with this command, no RT will be sent even if spam is sent.  
        The spam detection exception channel should be set for channels that use image bot commands such as NekoBot.  
        It is also recommended to add a slow mode to the channel when setting it.

        Parameters
        ----------
        mode : add or remove or list
            If `add` is set, the specified channel will be added to the list of channels not to be detected by spam.  
            If `remove` is set, the specified channel is removed from the list of channels not to be spammed.  
            If `list` is set, the list of channels without spam detection will be displayed.
        channel : text channel name/mention/id, optional
            The channel to add/remove.  
            This can be omitted if the `mode` argument is set to `list`.

        Aliases
        -------
        i"""
        if mode == "list":
            await self.reply(ctx, "\n".join(
                f"・<#{id_}>" for id_ in self.caches[ctx.guild.id][0].get("ignore", ())
            ))
        elif channel is not None:
            await self.setting(
                self.ignore_setting, ctx, mode, "ignore", channel, OK,
                nokeyerror=True
            )
        else:
            await self.reply(ctx, "使用方法が違います。", color="error")

    @automod.group(aliases=["w", "警告"])
    async def warn(self, ctx: commands.Context):
        """!lang ja
        -------
        警告数の設定をします。  
        RTがspamを検知したときに自動で警告数がたまっていきます。  
        そして最終的に設定されている警告数まで達した際にユーザーはタイムアウトまたはBANされます。

        Notes
        -----
        警告数は一日放置されるとリセットされます。  
        またスパムをしている人にはRTが怪しいと思います。  
        なのでもしRTに「これ以上スパムしたら...」とか言われた場合は、三分待機して嵐がすぎるを待ちましょう。

        Aliases
        -------
        w, 警告

        !lang en
        --------
        Set the number of warnings.  
        The number of warnings is, in essence, the degree to which you may be punished.  
        When you spam, the number of warnings will gradually increase.  
        Finally, when the number of warnings reaches the set number, you will be timed out or banned.

        Notes
        -----
        The number of warnings will be reset after a day of inactivity.  
        Also, if you are spamming, RT is suspicious.  
        So if RT says "If you don't stop spamming any more..." then wait for three minutes and wait for the storm to pass.

        Aliases
        -------
        w"""
        await self.automod(ctx)

    async def toggle(
        self, channel: Sendable, mode: str, value: Union[bool, Any], *args, **kwargs
    ):
        "onoffするだけの設定を更新する関数です。"
        if value is False:
            del self.caches[channel.guild.id][0][mode]
        else:
            if value is True:
                value = 1
            self.caches[channel.guild.id][0][mode] = \
                self.DEFAULTS.get(mode) if value is True else value
        return args, kwargs

    @warn.command(aliases=["l", "レベル"])
    async def level(
        self, ctx: commands.Context,
        mode: Literal["ban", "timeout", "mute"],
        warn: float
    ):
        """!lang ja
        --------
        警告数処罰レベルを設定します。  
        どれくらい警告数が上がったらBAN/タイムアウトをするかを設定することができます。

        Parameters
        ----------
        mode : ban または timeout
            `ban`にした場合はBANで`timeout`にした場合はタイムアウトに対する警告数を設定します。
        warn : float
            どれだけ警告数が上がったら`mode`引数の処罰を執行するかです。

        Notes
        -----
        デフォルトでは警告数が4になった際にタイムアウトで5になった際にBANが発生します。  
        もしスパムする人をタイムアウトせずにBANしたいという場合は、設定でBANの数をタイムアウトの数より少なくしましょう。

        Aliases
        -------
        l, レベル

        !lang en
        --------
        Sets the warning number punishment level.  
        This command can be used to set the level of banning/timeout when the warning count rises.

        Parameters
        ----------
        mode : ban or timeout
            If set to `ban`, it will be a ban, if set to `timeout`, it will be a timeout.
        warn : float
            The number of warnings to enforce for the `mode` argument.

        Notes
        -----
        The default is a timeout when the warning count reaches 4, and a ban when it reaches 5.  
        If you want to erase the message as well as the timeout if someone spams you, set the ban to 4 and the timeout to 5 etc.

        Aliases
        -------
        l"""
        if mode == "timeout":
            mode = "mute"
        await self.setting(self.toggle, ctx, mode, warn, OK)

    @warn.command(aliaess=["s", "設定"])
    async def set(self, ctx: commands.Context, warn: float, *, member: discord.Member):
        """!lang ja
        -------
        指定したメンバーの警告数を特定の数に設定します。

        Parameters
        ----------
        warn : float
            設定する警告数です。
        member : メンバーの名前かメンションまたはID
            設定するメンバーです。

        Aliases
        -------
        s, 設定

        !lang en
        --------
        Sets the number of warnings for a specific member to a specific number.

        Parameters
        ----------
        warn : float
            The number of warnings to set.
        member : member's name, mention or ID
            The member to set.

        Aliases
        -------
        s"""
        await self.prepare_cache_member(member)
        self.caches[ctx.guild.id][1][member.id].warn = warn
        await self.reply(ctx, OK)

    @warn.command(aliases=["c", "チェック", "確認"])
    async def check(self, ctx: commands.Context, *, member: discord.Member):
        """!lang ja
        --------
        指定したメンバーの警告数を確認します。

        Parameters
        ----------
        member : メンバーの名前かメンションまたはID
            警告数を確認したい対象のメンバーです。

        Aliases
        -------
        c, チェック, 確認

        !lang en
        --------
        Check the number of warnings for the specified member.

        Parameters
        ----------
        member : member's name, mention, or ID
            This is the member for which you want to check the number of warnings.

        Aliases
        -------
        c"""
        await self.prepare_cache_member(member)
        await self.reply(
            ctx, {
                "ja": f"{member.display_name}の現在の警告数は`{self.caches[ctx.guild.id][1][member.id].warn}`です。",
                "en": f"{member.display_name}'s current warn is {self.caches[ctx.guild.id][1][member.id].warn}."
            }
        )

    @automod.group(aliases=["iv", "招待リンク規制"])
    async def invites(self, ctx: commands.Context):
        """!lang ja
        --------
        招待リンク規制機能です。  
        この機能を有効にすると招待リンクを作れないようにすることができます。  
        この機能を有効にするには`rf!automod invites`と実行してください。

        Aliases
        -------
        iv, 招待リンク規制

        !lang en
        --------
        This is an invitation link restriction function.  
        If you enable this feature, you can prevent people from creating invitation links.  
        To enable this feature, run `rf!automod invites`.

        Aliases
        -------
        iv"""
        if not ctx.invoked_subcommand:
            await self.setting(
                self.ignore_setting, ctx, "toggle", "invites", None, OK
            )

    @invites.command("ignore", aliases=["i", "例外"])
    async def invites_ignore(
        self, ctx: commands.Context, mode: Literal["add", "remove", "list"],
        obj: Union[
            discord.Role, discord.Member, discord.TextChannel, discord.Object
        ] = None
    ):
        """!lang ja
        -------
        招待リンク規制の例外ロール,メンバー,チャンネルを設定するコマンドです。

        Parameters
        ----------
        mode : add または remove または list
            例外を追加するか削除するか現在指定されている例外のリストを表示するのどれかです。
        obj : ロール/メンバー/テキストチャンネルのメンションか名前またはID, optional
            例外として追加するロール,メンバー,テキストチャンネルです。  
            もし`mode`引数を`list`とした場合はこれは省略可能です。

        Aliases
        -------
        i, 例外

        !lang en
        --------
        This command is used to set the exception roles, members, and channels for the invitation link restriction.

        Parameters
        ----------
        mode : add or remove or list
            Add or remove exceptions, or display exception list.
        obj : Mention or name or ID of the role/member/text channel, optional
            The role, member, or text channel to add as an exception.  
            If the `mode` argument is set to `list`, this is optional.

        Aliases
        -------
        i"""
        if mode == "list":
            await self.reply(ctx, "\n".join(
                "".join((
                    "・", getattr(
                        ctx.guild.get_member(id_) or ctx.guild.get_role(id_)
                        or ctx.guild.get_channel(id_), "mention", id_
                    )
                )) for id_ in self.caches[ctx.guild.id][0].get("invites", ())
            ))
        else:
            assert obj is not None, "使用方法が違います。"
            await self.setting(self.ignore_setting, ctx, mode, "invites", obj, OK)

    @automod.group(aliases=["d", "削除"])
    async def deleter(self, ctx: commands.Context):
        """!lang ja
        --------
        招待リンク削除機能です。  
        これを有効にするとメッセージに招待リンクが含まれていた際にそのメッセージを消すようにすることができます。  
        この機能を有効にする場合は`rf!automod deleter`と実行してください。

        !lang en
        --------
        This is the Remove Invitation Link function.  
        If you enable this feature, you can delete a message when it contains an invitation link.  
        To enable this feature, run `rf!automod deleter`."""
        if not ctx.invoked_subcommand:
            await self.setting(
                self.ignore_setting, ctx, "toggle", "invite_deleter", None, OK
            )

    @deleter.command("ignore", aliases=["i", "例外"])
    async def deleter_ignore(
        self, ctx: commands.Context, mode: Literal["add", "remove", "list"],
        obj: str = None
    ):
        """!lang ja
        --------
        招待リンク削除機能に例外を設定します。  
        このコマンドを使えば削除しない招待リンクを登録することができます。

        Parameters
        ----------
        mode : add または remove または list
            例外の追加か削除かそのリストの表示です。
        obj : str, optional
            例外として追加する招待コードです。  
            もしリストを表示する場合はこの引数は省略可能です。

        Aliases
        -------
        i, 例外

        !lang en
        --------
        Sets an exception to the Delete Invite Link function.  
        You can use this command to register invitation links that will not be deleted.

        Parameters
        ----------
        mode : add or remove or list
            Add or remove exceptions, or display a list of them.
        obj : str, optional
            Invitation code to add as an exception.  
            If you want to display the list, this argument can be omitted.

        Aliases
        -------
        i"""
        if mode == "list":
            await self.reply(ctx, "\n".join(
                f"・{word}" for word in self.caches[ctx.guild.id][0]
                    .get("invite_deleter", ())
            ))
        else:
            assert obj is not None, "使用方法が違います。"
            await self.setting(
                self.ignore_setting, ctx, mode, "invite_deleter", obj, OK
            )

    @automod.command(aliases=["b", "即抜け"])
    async def bolt(self, ctx: commands.Context, seconds: Union[bool, float]):
        """!lang ja
        -------
        即抜けBAN機能です。  
        この機能を有効にすると新規参加者がサーバーを退出して指定した時間以内に再入室した際にBANをするようにできます。

        Parameters
        ----------
        seconds : 秒数かoff
            offにした場合はこの機能を無効に、秒数を指定した場合はその秒数で設定します。

        Aliases
        -------
        b, 即抜け

        !lang en
        --------
        This is an instant exit ban feature.  
        By enabling this feature, new participants will be banned when they leave the server and re-enter within the specified time.

        Parameters
        ----------
        seconds : off or some seconds
            Disables this feature if you turn it off with seconds off.

        Aliases
        -------
        b"""
        assert seconds in (True, False) or 0 <= seconds <= 900, "それより設定することはできません。"
        await self.setting(self.toggle, ctx, "bolt", seconds, OK)

    @automod.command(aliases=["e", "絵文字"])
    async def emoji(self, ctx: commands.Context, count: Union[bool, int]):
        """!lang ja
        --------
        絵文字規制機能です。  
        この機能を使えば指定した数以上絵文字を含んだメッセージを消すことができます。  
        またその絵文字大量送信を繰り返した場合は警告数を加算します。

        Parameters
        ----------
        count : offまたは個数
            何個送ったらメッセージを削除するかです。  
            `off`にした場合はこの機能を無効にします。

        Aliases
        -------
        e, 絵文字

        !lang en
        --------
        This is a pictogram restriction function.  
        With this function, you can delete messages that contain more than the specified number of pictograms.  
        If the number of pictograms is too high, a warning will be added.

        Parameters
        ----------
        count : off or number
            The number of pictograms that should not be sent.  
            If set to `off`, this feature will be disabled.

        Aliases
        -------
        e"""
        assert count in (True, False) or 0 <= count <= 4000, "その数で設定することはできません。"
        await self.setting(self.toggle, ctx, "emoji", count, OK)

    async def prepare_cache(self, guild: discord.Guild, member: discord.Member):
        await self.prepare_cache_guild(guild)
        await self.prepare_cache_member(member)

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if (message.guild and not message.author.bot
                and message.guild.id in self.enabled):
            await self.prepare_cache(message.guild, message.author)
            process_check_message(
                self.caches[message.guild.id][1][message.author.id],
                self.caches[message.guild.id][0], message
            )

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member):
        if member.guild.id in self.enabled:
            await self.prepare_cache(member.guild, member)
            await trial_new_member(
                self.caches[member.guild.id][1][member.id],
                self.caches[member.guild.id][0]
            )

    @commands.Cog.listener()
    async def on_invite_create(self, invite: discord.Invite):
        if invite.guild.id in self.enabled:
            await self.prepare_cache_guild(invite.guild)
            await trial_invite(self.caches[invite.guild.id][0], invite)


def setup(bot):
    bot.add_cog(AutoMod(bot))
