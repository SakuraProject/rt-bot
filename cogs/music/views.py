# RT Music - Views

from __future__ import annotations

from collections.abc import Coroutine, Callable, Iterator
from typing import TYPE_CHECKING, Literal, Union, Optional, Any

from inspect import iscoroutinefunction

import discord

from util import TimeoutView
from util.page import EmbedPage
from util.slash import Context, UnionContext

from .playlist import to_musics, Playlist
from .music import Music

if TYPE_CHECKING:
    from .__init__ import MusicCog


PLAYLIST_SELECT = {
    "ja": "プレイリストを選択してください。",
    "en": "Select the playlist."
}


def is_require_dj(self: MusicCog, author: discord.Member) -> tuple[bool, list[discord.Member]]:
    "DJが必要かどうかをチェックします。"
    return len(members := [
        member for member in author.voice.channel.members if not member.bot
    ]) > 1 \
        and author.get_role(
            self.dj[author.guild.id].dj if "dj" in self.dj[author.guild.id] else 0
        ) is None, members


class Confirmation(discord.ui.View):
    """DJ役職を持っていなくてもスキップをするためのボタンのViewです。
    `message`にこのViewを使ったメッセージオブジェクトを入れている必要があります。"""

    message: Optional[discord.Message] = None

    def __init__(self, coro: Coroutine, members: list[discord.Member], ctx: UnionContext):
        self.coro, self.number_members, self.members = coro, len(members), members
        self.confirmed: list[int] = []
        self.ctx = ctx
        super().__init__()

    @discord.ui.button(label="Confirm", emoji="✅")
    async def continue_(self, _, interaction: discord.Interaction):
        if interaction.user.id not in self.confirmed:
            self.confirmed.append(interaction.user.id)
        if (length := len(self.confirmed)) == self.number_members:
            await self.on_timeout()
            await interaction.response.send_message(
                {"ja": "全員納得したようなので実行しました。",
                 "en": "They all seemed to agree, so I did it."}
            )
            try:
                await self.coro
            except Exception as e:
                self.ctx.bot.dispatch("on_command_error", self.ctx, e)
        else:
            await interaction.response.send_message(
                f"Ok, Confirmed: {length}/{self.number_members}",
                ephemeral=True
            )

    async def on_timeout(self):
        # タイムアウトした場合は締め切る。
        if not self.is_finished():
            self.children[0].label = "Closed"
            self.children[0].disabled = True
            if self.message is not None:
                await self.message.edit(view=self)
            self.stop()


async def do_confirmation(
    coro: Coroutine, members: list[discord.Member], reply: Callable[..., Coroutine],
    ctx: UnionContext, **kwargs
):
    "DJがいない時のための募集ボタンを作ります。"
    if "content" not in kwargs:
        kwargs["content"] = {
        "ja": "他の人が音楽を聞いている場合はDJ役職がなければこれを実行することができません。\n"
            "または、以下のボタンをボイスチャンネルにいる人全員が押せば実行することができます。",
        "en": "If other people are also listening to the music, you will not be able to execute without a DJ role.\n"
            "Or, it can be done by having everyone in the voice channel press the following button."
    }
    view = Confirmation(coro, members, ctx)
    view.message = await reply(
        view=view, **kwargs
    )


def adjust_length(text: str, length: int = 100) -> str:
    return f"{text[:length-3]}..."


class MusicSelect(discord.ui.Select):
    "曲選択用のセレクトです。"

    def __init__(
        self, musics: list[Music], callback: Optional[
            Callable[[MusicSelect, discord.Interaction], Union[Coroutine, Any]]
        ] = None, **kwargs
    ):
        if "placeholder" not in kwargs:
            kwargs["placeholder"] = "Select music"
        self.max = kwargs.get("max_values", 5)
        super().__init__(**kwargs)
        self.musics, self.__callback = musics, callback
        self.init_options()

    def init_options(self):
        "オプションをリセットして`options`にあるものを追加します。"
        self.options = []
        for count, music in enumerate(self.musics):
            self.add_option(
                label=adjust_length(music.title), value=str(count),
                description=adjust_length(music.url)
            )
        # 最大選択数を調整する。
        self.max_values = count + 1 if count < self.max - 1 else self.max

    async def callback(self, interaction: discord.Interaction):
        if self.__callback is not None:
            if iscoroutinefunction(self.__callback):
                await self.__callback(self, interaction)
            else:
                self.__callback(self, interaction)


def _add_embed(
    embeds: list[discord.Embed], title: str, description: str,
    color: Union[discord.Color, int]
):
    embeds.append(discord.Embed(title=title, description=description, color=color))


def make_embeds(
    self: Queues, queues: list[Music], mode: Union[Literal["Queues"], str], range_: int = 5
) -> tuple[list[discord.Embed], list[list[Music]]]:
    "渡されたMusicのリストからEmbedのリストを作ります。"
    text, count, embeds, musics, tmp = "", 0, [], [], []
    for queue in queues:
        if mode == "Queues":
            text += f"\n{queue.author.mention}：{queue.marked_title}"
        else:
            text += f"\n{queue.marked_title}"
        count += 1
        tmp.append(queue)
        if count % range_ == 0:
            _add_embed(embeds, mode, text[1:], self.cog.bot.Colors.normal)
            musics.append(tmp)
            text, tmp = "", []
    if tmp and text:
        _add_embed(embeds, mode, text[1:], self.cog.bot.Colors.normal)
        musics.append(tmp)
    # 全ての埋め込みにページ数を書く。
    max_ = count / range_
    for page, embed in enumerate(embeds, 1):
        try:
            embeds[page]
        except IndexError:
            page = max_
        embed.set_footer(text=f"Pages {page}/{max_} | {count} songs")
    return embeds, musics


class MusicEmbedList(EmbedPage):
    "音楽リストのViewです。"

    def __init__(self, cog: MusicCog, musics: list[Music], title: str):
        self.cog = cog
        embeds, self.musics = make_embeds(self, musics, title)
        super().__init__(data=embeds)

    def on_page(self):
        assert isinstance(self.children[-1], MusicSelect), "Kaleidoscope pinging!"
        for child in self.children:
            if hasattr(child, "musics"):
                child.musics = self.musics[self.page]
                child.init_options()
        return {"view": self}


def process_musics(
    page: int, values: list[str], list_: list, mode: str = "yield"
) -> Optional[Iterator]:
    for index in sorted(map(int, values), reverse=True):
        index = page * 5 + index
        if mode == "del":
            del list_[index]
        else:
            yield list_[index]


def delete_musics(page: int, values: list[str], list_: list) -> None:
    "渡された音楽からSelectのvaluesのインデックスのものを消します。"
    next(process_musics(page, values, list_, "del"), None)


class Queues(MusicEmbedList):
    "キューリストのViewです。"

    def __init__(self, *args, **kwargs):
        kwargs["title"] = "Queues"
        super().__init__(*args, **kwargs)
        self.bot = self.cog.bot
        self.add_item(MusicSelect(
            self.musics[self.page], self.on_selected,
            placeholder="Queueの削除 ｜ Remove queues",
            max_values=5
        ))

    async def _process_queues(self, select, interaction):
        delete_musics(self.page, select.values, self.cog.now[interaction.guild_id].queues)
        self.stop()

    async def on_selected(self, select: MusicSelect, interaction: discord.Interaction):
        if (data := is_require_dj(self.cog, interaction.user))[0]:
            await do_confirmation(
                self._process_queues(select, interaction), data[1],
                interaction.response.edit_message, Context(
                    self.cog.bot, interaction, self, "rt!DREAMER", True
                ), content={
                    "ja": "他の人が音楽を聞いている場合はDJ役職がなければキューの削除を実行することができません。\n"
                        "または、以下のボタンをボイスチャンネルにいる人全員が押せば実行することができます。",
                    "en": "If other people are also listening to the music, you will not be able to delete queues without a DJ role.\n"
                        "Or, it can be done by having everyone in the voice channel press the following button."
                }, embed=discord.Embed(
                    title={"ja": "削除対象のキュー", "en": "Target queues"},
                    description="\n".join(
                        f"・{queue.marked_title}"
                        for queue in process_musics(
                            self.page, select.values, self.cog.now[interaction.guild_id].queues
                        )
                    ), color=self.bot.Colors.normal
                )
            )
        else:
            await interaction.response.edit_message(
                content={
                    "ja": f"{self.cog.EMOJIS.removed} キューを削除しました。",
                    "en": f"{self.cog.EMOJIS.removed} Removed queues"
                }, embed=None, view=None
            )
            self.stop()


class PlaylistSelect(discord.ui.Select):
    "プレイリスト選択用のSelect"

    def __init__(self, playlists: list[str], cog: MusicCog, **kwargs):
        self.cog = cog
        super().__init__(**kwargs)
        for name in playlists:
            self.add_option(label=name, value=name)


class AddMusicPlaylistSelect(PlaylistSelect):
    "プレイリストに曲を追加するのに使うSelect"

    song: str

    async def callback(self, interaction: discord.Interaction):
        # PlaylistSelectで選択されたプレイリストに音楽を追加する。
        if isinstance(self.song, str):
            await interaction.response.edit_message(
                content="Now loading...", view=None
            )
            data = await Music.from_url(
                self, interaction.user, self.song, self.cog.max(interaction.user)
            )
        else:
            # nowコマンドから登録しようとした場合はURLではなくMusicなのでそのままdataに入れる。
            data = self.song
        playlist = self.cog.get_playlist(interaction.user.id, self.values[0])
        try:
            if isinstance(data, Music):
                playlist.add(data)
            elif isinstance(data, tuple):
                playlist.extend(data[0])
            else:
                return await interaction.response.edit_message(
                    content=f"何かしらエラーが発生しました。 / Something went to wrong.\nCode: `{data}`",
                    view=None
                )
        except AssertionError as e:
            kwargs = dict(content=e.args[0], view=None)
        else:
            kwargs = dict(content="設定しました。", view=None)
        if interaction.response.is_done():
            await interaction.edit_original_message(**kwargs)
        else:
            await interaction.response.edit_message(**kwargs)


class PlaylistMusics(MusicEmbedList):
    "プレイリストにある音楽のリストを表示するためのView"

    def __init__(self, playlist_name: str, *args, **kwargs):
        self.playlist_name = playlist_name
        kwargs["title"] = "Playlist"
        super().__init__(*args, **kwargs)
        for placeholder, select in (
            ("曲の削除 ｜ Remove music", self.on_selected),
            ("曲の再生 ｜ Play music", self.on_play_selected)
        ):
            self.add_item(MusicSelect(
                self.musics[self.page], select, placeholder=placeholder
            ))

    def get_playlist(self, interaction: discord.Interaction) -> Playlist:
        return self.cog.get_playlist(interaction.user.id, self.playlist_name)

    async def on_selected(self, select: MusicSelect, interaction: discord.Interaction):
        playlist = self.get_playlist(interaction)
        delete_musics(self.page, select.values, playlist.data)
        self.cog.data[interaction.user.id].playlists[self.playlist_name] = playlist.data

        # 空なら丸ごと消す。
        if not self.cog.data[interaction.user.id].playlists:
            del self.cog.data[interaction.user.id]

        await interaction.response.edit_message(content={
            "ja": "削除しました。", "en": "Removed"
        }, embed=None, view=None)

    async def on_play_selected(self, select: MusicSelect, interaction: discord.Interaction):
        if interaction.user.voice is None:
            await interaction.response.edit_message(
                content={
                    "ja": "ボイスチャンネルに参加してください。",
                    "en": "You must be connected to a voice channel."
                }, embed=None, view=None
            )
        else:
            await self.cog._play(
                Context(self.cog.bot, interaction, self.cog.play, "rt!play"),
                to_musics(
                    list(process_musics(
                        self.page, select.values, self.get_playlist(
                            interaction
                        ).data
                    )),
                    self.cog, interaction.user
                )
            )


class ShowPlaylistSelect(PlaylistSelect):
    "プレイリストの曲を表示する時のプレイリスト選択に使うSelect"

    async def callback(self, interaction: discord.Interaction):
        if (playlist := self.cog.get_playlist(interaction.user.id, self.values[0])).data:
            view = PlaylistMusics(
                self.values[0], self.cog, playlist.to_musics(self.cog, interaction.user)
            )
            await interaction.response.edit_message(content=None, embed=view.data[0], view=view)
        else:
            await interaction.response.edit_message(content="このプレイリストは空です。", embed=None, view=None)


class PlayPlaylistSelect(PlaylistSelect):
    "プレイリストの曲を全て再生またはキューに追加する際に使うSelect"

    async def callback(self, interaction: discord.Interaction):
        await self.cog._play(
            Context(self.cog.bot, interaction, self.cog.play, "rt!play"),
            self.cog.get_playlist(interaction.user.id, self.values[0]).to_musics(
                self.cog, interaction.user
            )
        )


class AddMusicPlaylistView(TimeoutView):
    "nowコマンドで表示した際に入れるプレイリストに登録ボタンです。"

    def __init__(self, music: Music, cog: MusicCog, *args, **kwargs):
        self.music, self.cog = music, cog
        super().__init__(*args, **kwargs)

    @discord.ui.button(
        label="プレイリストに追加 ｜ Add to playlist",
        style=discord.ButtonStyle.green, emoji="➕"
    )
    async def add_to_playlist(
        self, button: discord.ui.Button, interaction: discord.ui.Interaction
    ):
        try:
            self.cog.assert_playlist(interaction.user.id)
            view = TimeoutView()
            view.add_item(
                select := AddMusicPlaylistSelect(
                    self.cog.data[interaction.user.id].playlists, self.cog
                )
            )
            select.song = self.music
        except AssertionError as e:
            await interaction.response.send_message(e, ephemeral=True)
        else:
            view.message = await interaction.response.send_message(
                PLAYLIST_SELECT, view=view, ephemeral=True
            )