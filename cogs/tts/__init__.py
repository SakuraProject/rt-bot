# Free RT - TTS

from __future__ import annotations

from typing import TypedDict, TypeVar, Literal, Union, Optional, Any

from functools import wraps
from os import listdir

from discord.ext import commands, tasks
import discord

from aiofiles.os import remove

from util.slash import UnionContext
from util import RT, Table
from util import TimeoutView

from .agents import OPENJTALK, AGENTS
from .voice import OUTPUT_DIRECTORY
from .manager import Manager


class RoutineData(TypedDict):
    keys: list[str]
    path: str


class TTSUserData(Table):
    __allocation__ = "UserID"
    routines: list[RoutineData]
    voice: str


class TTSGuildData(Table):
    __allocation__ = "GuildID"
    dictionary: dict[str, str]


DecoFuncT = TypeVar("DecoFuncT")
def check(func: DecoFuncT) -> DecoFuncT:
    "読み上げの設定を変更可能かどうかチェックするデコレータ"
    @wraps(func)
    async def new(self: TTSCog, ctx: UnionContext, *args, **kwargs):
        if ctx.guild.id not in self.now:
            await ctx.reply({
                "ja": "まだ読み上げを開始していません。",
                "en": "It has not yet started tts."
            })
        else:
            return await func(self, ctx, *args, **kwargs)
    return new


class SelectAgentView(TimeoutView):
    "AgentセレクトのViewです。"

    def __init__(self, cog: TTSCog, *args, **kwargs):
        self.cog = cog
        super().__init__(*args, **kwargs)

    @discord.ui.select(
        placeholder="Select agent", options=[
            discord.SelectOption(
                label=agent.name, value=agent.code,
                description=agent.details, emoji=agent.emoji
            ) for agent in AGENTS.values()
        ]
    )
    async def agent_select(self, select: discord.ui.Select, interaction: discord.Interaction):
        self.cog.user[interaction.user.id].voice = select.values[0]
        await interaction.response.send_message({"ja": "設定しました。", "en": "Ok"})


class TTSCog(commands.Cog, name="TTS"):

    RTCHAN = False

    def __init__(self, bot: RT):
        self.bot = bot

        self.user = TTSUserData(self.bot)
        self.guild = TTSGuildData(self.bot)
        self.auto_leave.start()

        self.RTCHAN = self.bot.user.id == 888635684552863774
        global OPENJTALK
        if self.RTCHAN:
            # もしりつたんの場合はOpenJTalkの場所を直接指定する。
            OPENJTALK = "/home/tasuren/opt/bin/open_jtalk"

        self.now: dict[int, Manager] = {}

    @commands.group(aliases=("読み上げ",), extras={
        "headding": {"ja": "読み上げ", "en": "TTS"}, "parent": "Entertainment"
    })
    async def tts(self, ctx: UnionContext):
        """!lang ja
        --------
        読み上げ機能です。

        !lang en
        --------
        TTS"""
        if not ctx.invoked_subcommand:
            await ctx.reply({
                "ja": "使用方法が違います。", "en": "It is wrong way to use this feature."
            })

    @tts.command(aliases=("start", "s", "j", "開始", "参加"))
    @commands.cooldown(1, 10, commands.BucketType.guild)
    async def join(self, ctx: UnionContext):
        """!lang ja
        --------
        読み上げを開始します。

        Aliases
        -------
        start, s, j, 開始, 参加

        !lang en
        --------
        Start TTS.

        Aliases
        -------
        start, s, j"""
        if ctx.guild.voice_client:
            await ctx.reply({
                "ja": "既に別のチャンネルに接続しています。",
                "en": "It is already connected to another channel."
            })
        elif ctx.author.voice is None:
            await ctx.reply({
                "ja": "ボイスチャンネルに接続してください。",
                "en": "You must be connected to a voice channel."
            })
        elif ctx.guild.id in self.bot.cogs["Music"].now:
            await ctx.reply({
                "ja": "音楽プレイヤーと同時に使うことはできません。",
                "en": "Cannot be used with a music player at the same time.\nWe are currently preparing English support for Ritsu-chan, our sub RT.\nPlease wait for it to be released."
            })
        else:
            await ctx.author.voice.channel.connect()
            self.now[ctx.guild.id] = Manager(self, ctx.guild)
            self.now[ctx.guild.id].add_channel(ctx.channel.id)
            await ctx.reply({"ja": "接続しました。", "en": "Connected!"})

    @tts.command(aliases=("l", "さようなら"))
    async def leave(self, ctx: UnionContext):
        """!lang ja
        --------
        読み上げを終了します。

        Aliases
        -------
        l, さようなら

        !lang en
        --------
        Stop tts

        Aliases
        -------
        l"""
        if ctx.guild.id in self.now:
            self.clean(self.now[ctx.guild.id])
        else:
            try: await ctx.guild.voice_client.disconnect()
            except Exception: ...
        await ctx.reply("Bye!")

    @tts.command(aliases=("v", "声", "agent"))
    @commands.cooldown(1, 5, commands.BucketType.user)
    async def voice(self, ctx: UnionContext):
        """!lang ja
        --------
        読み上げで使う音声を変更します。

        Aliases
        -------
        v, agent, 声

        !lang en
        --------
        Change voice that will be used when do TTS.

        Notes
        -----
        For those who set the language setting to English, gTTS (For english) will be set by default.
        If you are speaking in English, you may want to set it to gTTS, as anything other than gTTS will not be pronounced well.

        Aliases
        -------
        v, agent"""
        await ctx.reply({
            "ja": "音声を選んでください。", "en": "Choose your voice."
        }, view=SelectAgentView(self))

    @tts.command(aliases=("ch", "チャンネル"))
    async def channel(self, ctx: UnionContext, mode: Literal["toggle", "list"]):
        """!lang ja
        ---------
        読み上げ対象チャンネルを設定します。
        最大十個まで設定が可能です。

        Parameters
        ----------
        mode : toggle / list
            `toggle`にした場合は実行したチャンネルを読み上げるか読み上げないかを切り替えます。
            `list`にした場合は現在設定されている読み上げの対象のチャンネルの一覧を表示します。

        Aliases
        -------
        ch, チャンネル

        !lang en
        --------
        Sets the target channel for reading out.
        A maximum of ten channels can be set.

        Parameters
        ----------
        mode : toggle / list
            When set to `toggle`, toggles between reading out the current channel and not reading out the current channel.
            If set to `list`, it will display the list of channels that are currently set to be read out.

        Aliases
        -------
        ch"""
        if mode == "toggle":
            if not self.now[ctx.guild.id].remove_channel(ctx.channel.id):
                self.now[ctx.guild.id].add_channel(ctx.channel.id)
            await ctx.reply("Ok")
        else:
            await ctx.reply(embed=discord.Embed(
                title={"ja": "読み上げ対称チャンネル", "en": "TTS Target Channel"},
                description="\n".join(
                    f"・<#{channel_id}>" for channel_id in self.now[ctx.guild.id].channels
                ), color=self.bot.Colors.normal
            ))

    def _assert_dict(self, ctx: UnionContext):
        assert "dictionary" in self.guild[ctx.guild.id], {
            "ja": "まだ辞書には何も設定されていません。", "en": "Nothing has been set in the dictionary yet."
        }

    @tts.group(aliases=("dic", "dict", "辞書"))
    async def dictionary(self, ctx: UnionContext):
        """!lang ja
        --------
        辞書を設定します。
        辞書というのは特定の文字列があれば別の文字列に置き換えるというものです。
        `rt!tts dictionary`と実行することで登録されているワードの一覧を表示できます。

        Aliases
        -------
        dic, dict, 辞書

        !lang en
        --------
        Set up a dictionary.
        A dictionary is a string of characters that, if present, will be replaced by another string.
        `rt!tts dictionary` to displays words registered.

        Aliases
        -------
        dic, dict"""
        if ctx.invoked_subcommand:
            await ctx.reply("Ok")
        else:
            self._assert_dict(ctx)
            await ctx.reply(embed=discord.Embed(
                title={"ja": "辞書", "en": "Dictionary"},
                description="\n".join(
                    f"{before}：{after}" for before, after in list(
                        self.guild[ctx.guild.id].dictionary.items()
                    )
                ), color=self.bot.Colors.normal
            ))

    @dictionary.command(aliases=("設定", "s"))
    async def set(self, ctx: UnionContext, before, *, after):
        """!lang ja
        --------
        辞書を設定します。

        Parameters
        ----------
        before : str
            置き換える対象の文字列
        after : str
            置き換え後の文字列

        Aliases
        -------
        s, 設定

        !lang en
        --------
        Sets the dictionary.

        Parameters
        ----------
        before : str
            The target string
        after : str
            The string to be replaced

        Aliases
        -------
        s"""
        if "dictionary" not in self.guild[ctx.guild.id]:
            self.guild[ctx.guild.id].dictionary = {}
        self.guild[ctx.guild.id].dictionary[before] = after

    @dictionary.command(aliases=("del", "rm", "remove", "削除"))
    async def delete(self, ctx: UnionContext, *, before):
        """!lang ja
        --------
        辞書を削除します。

        Parameters
        ----------
        before : str
            置き換え対象の文字列

        Aliases
        -------
        del, rm, remove, 削除

        !lang en
        --------
        Delete dictionary

        Parameters
        ----------
        before : str
            Target string

        Aliases
        -------
        del, rm, remove"""
        self._assert_dict(ctx)
        assert before in self.guild[ctx.guild.id].dictionary, {
            "ja": "そのワードは設定されていません。", "en": "The word is not set."
        }
        del self.guild[ctx.guild.id].dictionary[before]

    def _assert_routine(self, ctx: UnionContext):
        assert "routines" in self.user[ctx.author.id], {
            "ja": "まだ何もRoutineは登録されていません。", "en": "Nothing has been registered for Routine yet."
        }

    @tts.group(aliases=("ネタ", "r", "meme"))
    async def routine(self, ctx: UnionContext):
        """!lang ja
        --------
        ネタ音声です。
        これは特定の音声を読み上げで流すことが可能です。
        例えば[そうだよ](https://commons.nicovideo.jp/material/nc115697)などです。
        `rt!tts routine`と実行することで登録されているRoutineのリストを表示することができます。

        Aliases
        -------
        r, meme, ネタ

        !lang en
        --------
        Meme player
        This can be used to play a meme voice on tts.
        Example: [hpg](https://www.youtube.com/watch?v=vjUqUVrXclE)
        You can display the list of registered Routines by running `rt!tts routine`.

        Aliases
        -------
        r, meme"""
        if not ctx.invoked_subcommand:
            self._assert_routine(ctx)
            await ctx.reply(embed=discord.Embed(
                title="Routines", description="\n".join(
                    f"・[{', '.join(routine['keys'])}]({routine['path']})"
                    for routine in self.user[ctx.author.id].routines
                ), color=self.bot.Colors.normal
            ))

    @routine.command("set", aliases=("s", "設定"))
    async def set_routine(self, ctx: UnionContext, voice: Union[Literal["up"], str], *, aliases):
        """!lang ja
        --------
        ネタ音声を設定します。

        Parameters
        ----------
        voice : URLまたはup
            ネタ音声のURLです。
            もしアップロードする場合はこれをupにしてファイルを添付してください。
        aliases : str
            カンマ(`,`)で区切った送信したら音声が流れる文字列です。

        Aliases
        -------
        s

        !lang en
        --------
        Setting meme voice

        Parameters
        ----------
        voice : URL or up
            The URL of the meme voice.
            If you want to upload the file, set this to up and attach the file.
        aliases : str
            A string of characters separated by commas (`,`) that will play the voice when sent.

        Aliases
        -------
        s, 設定"""
        assert voice.startswith("http") or ctx.message.attachments, {
            "ja": "音楽ファイルをアップロードするか音声ファイルのURLを指定してください。",
            "en": "Upload the music file or specify the URL of the audio file."
        }
        if "routines" not in self.user[ctx.author.id]:
            self.user[ctx.author.id].routines = []
        assert len(self.user[ctx.author.id].routines) < 20, {
            "ja": "これ以上設定できません。", "en": "No more settings can be made."
        }
        self.user[ctx.author.id].routines.append(RoutineData(
            keys=aliases.split(","), path=ctx.message.attachments[0].url
                if voice == "up" else voice
        ))
        await ctx.reply("Ok")

    @routine.command("delete", aliaess=("del", "rm", "remove", "削除"))
    async def delete_routine(self, ctx: UnionContext, *, alias):
        """!lang ja
        --------
        ネタ音声を削除します。

        Parameters
        ----------
        alias : str
            削除したいネタ音声の登録時に引数aliasesに指定したワードのどれかです。

        Aliases
        -------
        del, rm, remove, 削除

        !lang en
        --------
        Delete meme voice

        Parameters
        ----------
        alias : str
            This is one of the words specified in the argument aliases when registering the meme voice you want to delete.

        Aliases
        -------
        del, rm, remove"""
        self._assert_routine(ctx)
        for index, routine in enumerate(self.user[ctx.author.id].routines):
            if alias in routine["keys"]:
                del self.user[ctx.author.id].routines[index]
                await ctx.reply("Ok")
                break
        else:
            await ctx.reply({"ja": "見つかりませんでした。", "en": "Not found"})

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if message.guild and message.content and message.guild.id in self.now \
                and self.now[message.guild.id].check_channel(message.channel.id) \
                and not message.content.startswith(tuple(self.bot.command_prefix)):
            await self.now[message.guild.id].add(message)

    @commands.Cog.listener()
    async def on_voice_abandoned(self, voice_client: discord.VoiceClient):
        # 一人ぼっちになったのなら切断する。
        if voice_client.guild.id in self.now:
            self.clean(self.now[voice_client.guild.id], {
                "ja": "一人ぼっちになったので切断しました。", "en": "I was alone, so I disconnected."
            })

    @tasks.loop(seconds=10)
    async def auto_leave(self):
        # メンバーがいないのに接続している際はvoice_abandonedイベントを呼び出す。
        for voice_client in self.bot.voice_clients:
            if all(member.bot for member in voice_client.channel.members):
                self.bot.dispatch("voice_abandoned", voice_client)

    def clean(self, manager: Manager, reason: Optional[Any] = None) -> None:
        "渡されたManagerの後始末をします。"
        self.bot.loop.create_task(manager.disconnect(reason)) \
            .add_done_callback(lambda _: self.now.pop(manager.guild.id))

    def cog_unload(self):
        self.auto_leave.cancel()
        for manager in list(self.now.values()):
            self.clean(manager, {
                "ja": "再起動または機能更新のため切断しました。",
                "en": "Disconnected for reboot or feature update."
            })

        # もしお片付けされていないファイルがあるのなら削除しておく。
        for file_name in listdir(OUTPUT_DIRECTORY):
            if file_name.endswith(".wav"):
                self.bot.loop.create_task(remove(f"{OUTPUT_DIRECTORY}/{file_name}"))

    @commands.Cog.listener()
    async def on_voice_leave(self, member: discord.Member, _, __):
        # 強制切断されたらお片付けをする。
        if member.id == self.bot.user.id and member.guild.id in self.now \
                and not self.now[member.guild.id]._closing:
            self.clean(
                self.now[member.guild.id], {
                    "ja": "ｷｬｯ、誰かにVCから蹴られたかバグが発生しました。",
                    "en": "Ah, someone kicked me out of the VC or there was a bug."
                }
            )

    @commands.Cog.listener()
    async def on_voice_state_update(
        self, member: discord.Member,
        before: discord.VoiceState,
        after: discord.VoiceState
    ) -> None:
        # on_member_join/leaveのどっちかを呼び出すためのものです。
        if before.channel and after.channel and before.channel.id != after.channel.id:
            # もしメンバーがボイスチャンネルを移動したなら。
            self.bot.dispatch("voice_leave", member, before, after)
            self.bot.dispatch("voice_join", member, before, after)
        elif not before.channel:
            # もしメンバーがボイスチャンネルに接続したなら。
            self.bot.dispatch("voice_join", member, before, after)
        elif not after.channel:
            # もしメンバーがボイスチャンネルから切断したなら。
            self.bot.dispatch("voice_leave", member, before, after)


def setup(bot):
    bot.add_cog(TTSCog(bot))