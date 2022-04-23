# RT - Music

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import TypeVar, Literal, Union, Optional, Any

from functools import wraps
from asyncio import sleep

import discord.ext.commands as commands
import discord

from util.slash import loading, UnionContext, Context
from util import TimeoutView
from util import RT, Table, sendKwargs

from .views import (
    PLAYLIST_SELECT, is_require_dj, do_confirmation, MusicSelect, Queues,
    ShowPlaylistSelect, PlayPlaylistSelect, AddMusicPlaylistSelect, AddMusicPlaylistView
)
from .player import Player, NotAddedReason, LoopMode
from .music import MusicDict, Music
from .playlist import Playlist


IM_MACHINE = "私は夢見るマシーンです。"
class EMOJIS:
    start = "▶️"
    pause = "⏸"
    stop = "⏹"
    skip = "⏭"
    reversed_skip = "⏮"
    queued = "#️⃣"
    removed = "🌀"
    all_loop = "🔁"
    one_loop = "🔂"
    shuffle = "🔀"


class DJData(Table):
    __allocation__ = "GuildID"
    dj: int


class UserMusics(Table):
    __allocation__ = "UserID"
    playlists: dict[str, list[MusicDict]]


def kwargs(headding: dict[str, str], **kwargs) -> dict:
    kwargs["extras"] = {}
    kwargs["extras"]["headding"] = headding
    kwargs["extras"]["parent"] = "Music"
    return kwargs


DecoT = TypeVar("DecoT")
def check(check_state: bool = True, check_dj: bool = True) -> Callable[[DecoT], DecoT]:
    """音楽再生コマンドにつけるデコレータです。
    権限の確認等を行います。また、見出しをつけます。"""
    def decorator(func):
        original = func.callback
        @commands.cooldown(1, 3, commands.BucketType.user)
        @wraps(func._callback)
        async def new(self: MusicCog, ctx: commands.Context, *args, **kwargs):
            if not check_state:
                return await original(self, ctx, *args, **kwargs)

            if ctx.message.author.voice is None:
                await ctx.reply(
                    {"ja": "ボイスチャンネルに接続してください。",
                     "en": "You must be connected to a voice channel."}
                )
            elif ctx.guild.voice_client is None:
                return await ctx.reply(
                    {
                        "ja": "自分ボイスチャンネルに参加していないです。音楽再生をしてください。\n"
                            "*P.S.* もしボイスチャンネルにいるのにこうなる場合は`rt!disconnect on`を実行してください。",
                        "en": "I have not joined my own voice channel. Please play the music.\n"
                            "*P.S.* If this happens while you are on the voice channel, run `rt!disconnect on`."
                    }
                )
            elif check_dj and (data := is_require_dj(self, ctx.author))[0]:
                # DJがないといけないのに持っていない場合はコマンドを実行して良いか募集する。
                await do_confirmation(original(self, ctx, *args, **kwargs), data[1], ctx.reply, ctx)
            else:
                # チェックが済んだならメインを実行する。
                return await original(self, ctx, *args, **kwargs)
        func._callback = new
        return func
    return decorator


class MusicCog(commands.Cog, name="Music"):

    EMOJIS = EMOJIS

    def __init__(self, bot: RT):
        self.bot = bot
        self.now: dict[int, Player] = {}
        self.dj, self.data = DJData(self.bot), UserMusics(self.bot)

    def print(self, *args, **kwargs):
        "デバッグ用とかっこつけるためのprintです。"
        return self.bot.print("[MusicPlayer]", *args, **kwargs)

    def max(self, member: Union[discord.Member, discord.Guild, int] = None) -> int:
        "最大曲数を取得します。"
        return 800 # TODO: 課金要素を作ったら課金している人のみ1600にする。

    def get_player(self, guild_id: int) -> Optional[Player]:
        "指定されたGuildIDの音楽プレイヤーを返します。ただのエイリアス"
        return self.now.get(guild_id)

    @check(False)
    @commands.command(aliases=["p", "再生"], **kwargs({"ja": "音楽再生をします。", "en": "Play music"}))
    async def play(self, ctx: UnionContext, *, song: str = discord.SlashOption(
        "song", PDETAILS := "曲のURLまたは検索ワード｜Song url or search term"
    )):
        """!lang ja
        --------
        音楽再生を行います。

        Notes
        -----
        YouTubeとニコニコ動画とSoundCloudに対応しています。
        また、YouTubeの再生リストやニコニコ動画のマイリストの再生にも対応しています。
        もし他の曲の再生中にこのコマンドを実行した場合はキューという再生予定リストに登録されます。

        Parameters
        ----------
        song : str
            曲のURLまたは検索ワードです。

        Aliases
        -------
        p, 再生

        !lang en
        --------
        Play music.

        Notes
        -----
        Supported are YouTube, Nico Nico Douga, and SoundCloud.
        It also supports playback of YouTube playlists, and all songs in Nico Nico Douga's My List.
        If you run this command while another song is playing, new song will be added to the queue, which is a list of songs that are scheduled to be played.

        Parameters
        ----------
        song : str
            The url or search word of the song.

        Aliases
        -------
        p"""
        await loading(ctx)
        await self._play(ctx, song)

    def _get_status(self, status: Union[Exception, NotAddedReason]) -> Union[dict[str, str], str]:
        # 渡されたステータスから適切な返信を選びます。
        if isinstance(status, Exception):
            return {
                "ja": "楽曲の読み込みに失敗してしまいました。"
                    + (code := f"\ncode: `{status.__class__.__name__} - {status}`"),
                "en": f"Failed to load a music.{code}"
            }
        elif status == NotAddedReason.list_very_many:
            return {
                "ja": "リストが大きすぎたため後半の曲は追加されていません。",
                "en": "The second half of the song has not been added because the list was too large."
            }
        elif status == NotAddedReason.queue_many:
            return {
                "ja": "キューが満タンなため恐らくいくつかの曲が追加されていません。",
                "en": "Some songs have not been added, probably because the queue is full."
            }
        else:
            # ここは呼ばれたらおかしい。
            return IM_MACHINE

    async def _play(self, ctx: UnionContext, url: Union[str, Music, list[Music]]):
        # 曲を再生するための関数です。playコマンドの実装であり再呼び出しをする際の都合上別に分けています。
        assert ctx.guild is not None, "サーバーでなければ実行できません。"

        # 接続しているはずなのに接続していない場合、接続していないことにする。
        if (ctx.guild.id in self.now
            and ctx.guild.voice_client is None):
            del self.now[ctx.guild.id]
        # 接続していない場合は接続してPlayerを準備する。
        if ctx.guild.id not in self.now:
            assert ctx.author.voice is not None, {
                "ja": "あなたがVCに接続していなければ実行できません。",
                "en": "You have to connect to Voice to use this command."
            }
            try:
                vc = await ctx.author.voice.channel.connect()
            except discord.ClientException as e:
                if "Already" in str(e):
                    await ctx.author.voice.channel.disconnect()
                    await sleep(1.5)
                    vc = await ctx.author.voice.channel.connect()
                else: raise
            self.now[ctx.guild.id] = Player(self, ctx.guild, vc)
            self.now[ctx.guild.id].channel = ctx.channel

        status: Any = {}
        if isinstance(url, str):
            # 曲を読み込みむ。
            if (status := await self.now[ctx.guild.id].add_from_url(
                ctx.author, url
            )) is not None:
                if isinstance(status, list):
                    # リストの場合は検索結果のため選んでもらう。
                    view = TimeoutView()
                    view.add_item(MusicSelect(
                        status, lambda select, interaction: self.bot.loop.create_task(
                            self._play(
                                Context(
                                    ctx.bot, interaction, ctx.command,
                                    ctx.message.content, False, True
                                ), status[int(select.values[0])]
                            )
                        ), max_values=1
                    ))
                    view.message = await ctx.reply(
                        content={
                            "ja": "検索結果が複数あるので選んでください。",
                            "en": "There are multiple search results to choose from."
                        }, view=view
                    )
                    return
                else:
                    # もし何かしら発生したのなら警告を入れる。
                    status = self._get_status(status)
        elif isinstance(url, list):
            # `rt!playlist play`によってplayされた際にはurlにlist[Music]が入るのでここが実行される。
            for music in url:
                self.now[ctx.guild.id].add(music)
            ctx.reply_edit = True
        else:
            # 検索結果から選ばれた曲をキューに追加する。
            self.now[ctx.guild.id].add(url)

        # statusがもし空じゃないのなら危険と追記する。
        if status:
            status["ja"] = f"⚠️ 警告\n{status['ja']}\n"
            status["en"] = f"⚠️ Warnings\n{status['en']}\n"
        else:
            status = {"ja": "", "en": ""}

        if "code" in status["ja"]:
            return await ctx.reply(status)

        # 返信またはそれに加えて音楽再生の開始をする。
        if self.now[ctx.guild.id].vc.is_playing():
            await ctx.reply(
                content={
                    "ja": f"{status.get('ja', '')}{EMOJIS.queued} 曲をキューに追加しました。",
                    "en": f"{status.get('en', '')}{EMOJIS.queued} Queued"
                }, embed=None, view=None
            )
        else:
            assert (now := self.now[ctx.guild.id].now) is not None, IM_MACHINE
            view = AddMusicPlaylistView(now, self)
            view.message = await ctx.reply(
                content={
                    "ja": f"{status.get('ja', '')}{EMOJIS.start} 音楽再生を開始します。",
                    "en": f"{status.get('en', '')}{EMOJIS.start} Starting music player..."
                }, embed=now.make_embed(), view=view
            )
            await self.now[ctx.guild.id].play()

    @check()
    @commands.command(aliases=["stop", "dis", "切断"], **kwargs({"ja": "切断をします。", "en": "Disconnect"}))
    async def disconnect(self, ctx: UnionContext, force: bool = False):
        """!lang ja
        --------
        音楽再生を終了します。

        Notes
        -----
        `rt!disconnect on`とすると強制的に切断させることができます。

        Aliases
        -------
        stop, dis, 切断

        !lang en
        --------
        音楽再生を終了します。

        Notes
        -----
        `rt!disconnect on` to disconnect forcibly

        Aliases
        -------
        stop, dis"""
        try:
            await self.now[ctx.guild.id].disconnect(force=force)
        except KeyError:
            if ctx.guild.voice_client is not None:
                await ctx.guild.voice_client.disconnect(force=force)
        await ctx.reply(f"{EMOJIS.stop} Bye!")

    @check()
    @commands.command(aliases=["s", "スキップ"], **kwargs({"ja": "スキップをします。", "en": "Skip"}))
    async def skip(self, ctx: UnionContext):
        """!lang ja
        --------
        曲のスキップをします。

        Aliases
        -------
        s, スキップ

        !lang en
        --------
        Skip

        Aliases
        -------
        s"""
        self.now[ctx.guild.id].skip()
        await ctx.reply(f"{EMOJIS.skip} Skipped")

    @check()
    @commands.command(
        aliases=["rp", "loop", "ループ"], **kwargs({"ja": "ループの設定をします。", "en": "Toggle loop"})
    )
    async def repeate(self, ctx: UnionContext, mode: Literal["none", "all", "one", "auto"] = "auto"):
        """!lang ja
        --------
        ループの設定を切り替えます。

        Aliases
        -------
        rp, loop, ループ

        !lang en
        --------
        Toggle loop mode

        Aliases
        -------
        rp, loop"""
        now = self.now[ctx.guild.id].loop() if mode == "auto" \
            else self.now[ctx.guild.id].loop(getattr(LoopMode, mode))
        if now == LoopMode.none:
            content = {
                "ja": "🛑 リピート再生を無効にしました。",
                "en": "🛑 Disabled repeate."
            }
        elif now == LoopMode.all:
            content = {
                "ja": f"{EMOJIS.all_loop} 全曲リピート再生が有効になりました。",
                "en": f"{EMOJIS.all_loop} All song repeates are now enabled."
            }
        else:
            content = {
                "ja": f"{EMOJIS.one_loop} 一曲リピート再生が有効になりました。",
                "en": f"{EMOJIS.one_loop} One-song repeat playback is now enabled."
            }
        await ctx.reply(content)

    @check()
    @commands.command(aliases=["sfl", "シャッフル"], **kwargs({"ja": "シャッフルします。", "en": "Shuffle"}))
    async def shuffle(self, ctx: UnionContext):
        """!lang ja
        --------
        キューに追加されている曲をシャッフルします。

        !lang en
        --------
        Added queue"""
        self.now[ctx.guild.id].shuffle()
        await ctx.reply(f"{EMOJIS.shuffle} Shuffled")

    @check()
    @commands.command(aliases=["ps", "resume", "一時停止"], **kwargs({"ja": "一時停止します。", "en": "Pause"}))
    async def pause(self, ctx: UnionContext):
        """!lang ja
        --------
        曲を一時停止します。

        !lang en
        --------
        Pause"""
        await ctx.reply(
            f"{EMOJIS.start} Resumed"
            if self.now[ctx.guild.id].pause() else
            f"{EMOJIS.pause} Paused"
        )

    @check()
    @commands.command(aliases=["vol", "音量"], **kwargs({"ja": "音量を変更します。", "en": "Change volume"}))
    async def volume(self, ctx: UnionContext, volume: Optional[float] = None):
        """!lang ja
        --------
        音量を調整又は表示します。

        Parameters
        ----------
        volume : float, optional
            パーセントで音量を設定します。
            もしこの引数を指定しなかった場合は現在の音量を表示します。

        Aliases
        -------
        vol, 音量

        !lang en
        --------
        Adjusts or displays the volume.

        Parameters
        ----------
        volume : float, optional
            Sets the volume as a percentage.
            If this argument is not specified, the current volume will be displayed.

        Aliases
        -------
        vol"""
        if volume is None:
            await ctx.reply(f"Now volume: {self.now[ctx.guild.id].volume}")
        else:
            assert 0 <= volume <= 100, "音量は0から100の間である必要があります。"
            self.now[ctx.guild.id].volume = volume
            await ctx.reply("🔈 Changed")

    @check(True, False)
    @commands.command(
        aliases=["現在"], **kwargs({"ja": "現在再生中の曲を表示します。", "en": "Displays the currently playing music."})
    )
    async def now(self, ctx: UnionContext):
        """!lang ja
        --------
        現在再生中の曲の情報と経過時刻を表示します。
        また、プレイリストに追加ボタンもついています。

        Aliases
        -------
        現在

        !lang en
        --------
        Displays currently playing music information."""
        assert self.now[ctx.guild.id].now is not None, {
            "ja": "現在何も再生していません。", "en": "I'm not playing anything."
        }
        view = AddMusicPlaylistView(self.now[ctx.guild.id].now, self)
        view.message = await ctx.reply(
            embed=self.now[ctx.guild.id].now.make_embed(True), view=view
        )

    @check(True, False)
    @commands.command(
        aliases=["キュー", "qs"], **kwargs(
            {"ja": "現在登録されているキューを表示します。", "en": "Displays currently queues registered."}
        )
    )
    async def queues(self, ctx: UnionContext):
        """!lang ja
        --------
        現在登録されているキューのリストを表示します。
        また、キューの削除も行うことができます。

        !lang en
        --------
        Displays queues list."""
        view = Queues(self, self.now[ctx.guild.id].queues)
        view.message = await ctx.reply(embed=view.data[0], view=view)

    @check(False)
    @commands.group(
        aliases=["pl", "プレイリスト", "再生リスト"], **kwargs(
            {"ja": "プレイリスト", "en": "Playlist"}
        )
    )
    async def playlist(self, ctx: UnionContext):
        """!lang ja
        ---------
        プレイリストです。
        十個までプレイリストを作成することができます。
        また、一つのプレイリストには八百曲まで登録することができます。
        `rt!playlist`で現在登録されているプレイリストの一覧を表示します。

        Aliases
        -------
        pl, プレイリスト, 再生リスト

        !lang en
        --------
        Playlists.
        You can create up to ten playlists.
        Also, up to 800 songs can be registered in one playlist.
        `rt!playlist` to displays list of playlists created.

        Aliases
        -------
        pl"""
        if not ctx.invoked_subcommand:
            self.assert_playlist(ctx.author.id)
            await ctx.reply(embed=discord.Embed(
                title={
                    "ja": "あなたのプレイリスト",
                    "en": "Playlists"
                }, description="\n".join(
                    f"・{name}" for name in list(self.data[ctx.author.id].playlists.keys())
                ), color=self.bot.Colors.normal
            ))

    def assert_playlist(self, author_id: int):
        "プレイリストを作っているかのチェックをします。"
        assert "playlists" in self.data[author_id], {
            "ja": "現在あなたはプレイリストを所有していません。\n`rt!playlist create <名前>`で作成可能です。",
            "en": "Currently, You don't have any playlists.\n`rt!playlist create <NAME>` to create a playlist."
        }

    def get_playlist(self, author_id: int, name: str) -> Playlist:
        "Playlistを取得します。"
        self.assert_playlist(author_id)
        assert name in self.data[author_id].playlists, "そのプレイリストが見つかりませんでした。"
        return Playlist(self.data[author_id].playlists[name], self.max(author_id))

    @playlist.command(
        aliases=["c", "new", "作成"], description="プレイリストを新規作成します。｜Create a playlist"
    )
    async def create(self, ctx: UnionContext, *, name: str = discord.SlashOption(
        "name", PN := "プレイリストの名前です。｜Playlist name"
    )):
        """!lang ja
        --------
        プレイリストを作成します。

        Parameters
        ----------
        name : str
            作成するプレイリストの名前です。

        Aliases
        -------
        c, new, 作成

        !lang en
        --------
        Create playlist.

        Parameters
        ----------
        name : str
            The name of the playlist to create.

        Aliases
        -------
        c, new"""
        if "playlists" not in self.data[ctx.author.id]:
            self.data[ctx.author.id].playlists = {}
        assert len(self.data[ctx.author.id].playlists) < 10, {
            "ja": "これ以上作れません。", "en": "You can't create playlist more than 10."
        }
        if name in self.data[ctx.author.id].playlists:
            await ctx.reply({
                "ja": "既にその名前のプレイリストは存在します。",
                "en": "That name playlist is already exists."
            })
        else:
            self.data[ctx.author.id].playlists[name] = []
            await ctx.reply("Ok")

    @playlist.command(
        aliases=["rm", "del", "削除"], description="プレイリストを削除します。｜Delete playlist"
    )
    async def delete(self, ctx: UnionContext, *, name: str = discord.SlashOption("name", PN)):
        """!lang ja
        --------
        プレイリストを削除します。

        Parameters
        ----------
        name : str
            プレイリストの名前です。

        Aliases
        -------
        rm, del, 削除

        !lang en
        --------
        Delete playlist

        Parameters
        ----------
        name : str
            Playlist name

        Aliases
        -------
        rm, del"""
        self.get_playlist(ctx.author.id, name)
        del self.data[ctx.author.id].playlists[name]
        await ctx.reply("Ok")

    @playlist.command(aliases=["a", "追加"])
    async def add(self, ctx: UnionContext, *, url: str = discord.SlashOption("url", PDETAILS)):
        """!lang ja
        --------
        プレイリストに曲を追加します。

        Parameters
        ----------
        url : str
            追加する曲,YouTubeの再生リスト,ニコニコ動画のマイリストのどれかのURLです。

        Aliases
        -------
        a, 追加

        !lang en
        --------
        Adds a song to the playlist.

        Parameters
        ----------
        url : str
            The URL of the song to add, or the URL of the YouTube playlist or Nico Nico Douga My List.

        Aliases
        -------
        a"""
        self.assert_playlist(ctx.author.id)
        assert self.data[ctx.author.id].playlists, "プレイリストがまだ作られていません。"
        view = TimeoutView()
        view.add_item(select:=AddMusicPlaylistSelect(
            self.data[ctx.author.id].playlists, self
        ))
        select.song = url
        view.message = await ctx.reply(
            PLAYLIST_SELECT,
            view=view, **sendKwargs(ctx, ephemeral=True)
        )

    async def _run_playlist_command(self, ctx, name, content=PLAYLIST_SELECT):
        self.assert_playlist(ctx.author.id)
        view = TimeoutView()
        view.add_item(globals()[name](self.data[ctx.author.id].playlists, self))
        view.message = await ctx.reply(content, view=view, **sendKwargs(ctx, ephemeral=True))

    @playlist.command(aliases=["s", "表示"])
    async def show(self, ctx: UnionContext):
        """!lang ja
        ---------
        プレイリストにある曲を表示します。
        また選択して曲の削除や再生もすることが可能です。

        Aliases
        -------
        s, 表示

        !lang en
        --------
        Displays the songs in the playlist.
        You can also delete or play songs by selecting them.

        Aliases
        -------
        s"""
        await self._run_playlist_command(ctx, "ShowPlaylistSelect")

    @playlist.command("play", aliases=["p", "再生"])
    async def playlist_play(self, ctx: UnionContext):
        """!lang ja
        --------
        プレイリストにある曲を全て再生します。

        Aliases
        -------
        p, 再生

        !lang en
        --------
        Play musics included in playlist.

        Aliases
        -------
        p"""
        await self._run_playlist_command(ctx, "PlayPlaylistSelect")

    @check(False)
    @commands.command(aliases=["だーじぇー"], **kwargs({"ja": "DJの設定をします。", "en": "Setting dj"}))
    @commands.has_guild_permissions(manage_roles=True)
    async def dj(self, ctx: UnionContext, *, role: Union[discord.Role, bool]):
        """!lang ja
        --------
        DJロールの設定をします。

        Parameters
        ----------
        role : ロールのメンションか名前またはIDそれか`off`
            DJロールとして設定するロールです。
            もし`off`とした場合はDJロールをなくします。

        Aliases
        -------
        だーじぇー

        !lang en
        --------
        Setting DJ role

        Parameters
        ----------
        role : Role's mention, name or ID or `off`
            DJ Role
            If you type `off`, dj role will not be set."""
        if role is False:
            if "dj" in self.dj[ctx.guild.id]:
                del self.dj[ctx.guild.id]
        else:
            self.dj[ctx.guild.id].dj = role.id
        await ctx.reply("Ok")

    def cog_unload(self):
        # コグがアンロードされた際にもし使用されてる音楽プレイヤーがあれば終了する。
        for player in list(self.now.values()):
            self.bot.loop.create_task(
                player.disconnect(
                    {"ja": "すみませんが再起動または音楽プレイヤーの更新のため音楽再生を終了します。",
                     "en": "Sorry, music playback will be terminated due to reboot or music player update."}
                ), name=f"{player}.disconnect"
            )

    def remove_player(self, guild_id: int):
        "音楽プレイヤーを削除するだけの関数です。"
        del self.now[guild_id]

    @commands.Cog.listener()
    async def on_voice_abandoned(self, voice_client: discord.VoiceClient):
        # 放置された場合は切断する。
        if voice_client.guild.id in self.now:
            await self.now[voice_client.guild.id].disconnect(
                {"ja": "一人ぼっちになったので切断しました。",
                 "en": "I was alone, so I disconnected."}
            )

    @commands.Cog.listener()
    async def on_voice_leave(self, member: discord.Member, _, __):
        if member.id == self.bot.user.id and member.guild.id in self.now \
                and not self.now[member.guild.id]._closing:
            await self.now[member.guild.id].disconnect(
                {
                    "ja": "ｷｬｯ、誰かにVCから蹴られたかバグが発生しました。",
                    "en": "Ah, someone kicked me out of the VC or there was a bug."
                }
            )


def setup(bot):
    bot.add_cog(MusicCog(bot))
