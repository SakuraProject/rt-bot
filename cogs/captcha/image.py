# Free RT Captcha - Image

from __future__ import annotations

from typing import TYPE_CHECKING, Union, Optional

from random import randint
from io import BytesIO

import discord

from captcha.image import ImageCaptcha as ImageGenerator
from aiofiles.os import remove as aioremove
from aiofiles import open as aioopen
from aiohttp import FormData

from jishaku.functools import executor_function

if TYPE_CHECKING:
    from .__init__ import Captcha, Mode
    from .web import WebCaptchaView
    from .click import ClickCaptcha


class QueueData:
    mode: "Mode"
    role_id: int
    characters: str
    path: str


async def response(
    interaction: discord.Interaction, content: str, send: bool = False
) -> None:
    "返信をして埋め込みとViewを消す関数です。また、返信のみもできます。"
    if send:
        return await interaction.response.send_message(
            content=content, ephemeral=True
        )
    else:
        return await interaction.response.edit_message(
            content=content, embed=None, view=None
        )


async def add_roles(
    view: Union[SelectView, WebCaptchaView, ClickCaptcha],
    interaction: discord.Interaction, send: bool = False
):
    "役職を付与してinteractionの返信をする関数です。"
    if (role := interaction.guild.get_role(
        view.captcha.cog.queue[interaction.guild_id][interaction.user.id][2].role_id
    )):
        try:
            await interaction.user.add_roles(role)
        except discord.Forbidden:
            await response(interaction, "権限がないため役職の付与に失敗しました。", send)
        else:
            await response(interaction, "認証に成功しました。", send)
            return await view.on_success(
                interaction.guild_id, interaction.user.id
            )
    else:
        await response(interaction, "役職が見つからないため役職の付与ができませんでした。", send)
    await view.on_failed(interaction.guild_id, interaction.user.id)


def make_random_string(length: int):
    "ランダムな数字の文字列を指定された長さだけ作ります。"
    return "".join(str(randint(0, 9)) for _ in range(length))


class Select(discord.ui.Select):
    "画像認証の画像にある文字を選択するセレクターのクラスです。"

    view: Union[SelectView, WebCaptchaView]

    def __init__(self, view, *args, **kwargs):
        if "placeholder" not in kwargs:
            kwargs["placeholder"] = "The number in the image | 画像にあった数字"
        super().__init__(*args, **kwargs)
        # 答えの言葉以外の言葉を選択肢に追加する。
        words = []
        for _ in range(9):
            while (
                word := make_random_string(view.captcha.password_length)
            ) in words or word == view.characters:
                ...
            words.append(word)
        words.insert(randint(0, len(words)), view.characters)
        for word in words:
            self.add_option(label=word, value=word)
        del words

    async def callback(self, interaction: discord.Interaction):
        if self.values[0] == self.view.characters:
            return await add_roles(self.view, interaction)
        else:
            await interaction.response.edit_message(
                content="画像にある文字列と違います。", embed=None, view=None
            )
        # 認証失敗時には認証用の画像を作り直す。
        await self.view.on_failed(
            interaction.guild_id, interaction.user.id
        )


class SelectView(discord.ui.View):
    "画像認証の数字の文字列のセレクターのViewです。"

    def __init__(
        self, captcha: ImageCaptcha, characters: str, url: str, *args, **kwargs
    ):
        self.captcha, self.characters = captcha, characters
        self.on_failed, self.on_success = \
            self.captcha.update_image, self.captcha.cog.remove_queue
        super().__init__(*args, **kwargs)
        self.add_item(Select(self))
        self.add_item(discord.ui.Button(label="Let's see picture | 画像を見る", url=url))


class ImageCaptcha(ImageGenerator):
    "画像認証の関数をまとめるためのクラスです。"

    BASE_PATH = "data/captcha/"

    def __init__(
        self, cog: Captcha, font_path: str = f"{BASE_PATH}SourceHanSans-Normal.otf",
        password_length: int = 5
    ):
        self.cog, self.password_length = cog, password_length
        super().__init__(fonts=[font_path])

    @executor_function
    def create_image(self, path: str, characters: Optional[str] = None) -> str:
        "Captcha用の画像を生成します。"
        self.write(
            characters := characters or make_random_string(
                self.password_length
            ), path
        )
        return characters

    def make_filename(self, guild_id: int, user_id: int) -> str:
        return f"{guild_id}-{user_id}.png"

    def make_path(self, guild_id: int, user_id: int) -> str:
        return f"{self.BASE_PATH}{self.make_filename(guild_id, user_id)}"

    async def update_image(self, guild_id: int, member_id: int) -> tuple[str, str]:
        "認証用の画像を更新します。まだない場合は新規作成します。"
        # 認証用の画像を作りキューにその画像にある文字とパスを保存しておく。
        self.cog.queue[guild_id][member_id][2].path = path = \
            self.make_path(guild_id, member_id)
        self.cog.queue[guild_id][member_id][2].characters = characters = \
            await self.create_image(path)
        # 画像をウェブサーバーに送信する。
        async with self.cog.session() as session:
            async with aioopen(path, "rb") as f:
                await session.post(
                    f"{self.cog.bot.get_url()}{self.cog.BASE}image/post",
                    data=FormData({"file": BytesIO(await f.read())}),
                    params={"path": self.make_path(guild_id, member_id)}
                )
            self.cog.print("[Image.Upload]", path)
        self.cog.bot.loop.create_task(aioremove(path))
        return characters

    async def on_queue_remove(self, guild_id: int, member_id: int, _) -> None:
        # キューの削除時にはウェブサーバーに認証用の画像を消すように指示する。
        await self.remove_image(guild_id, member_id)

    async def remove_image(self, guild_id: int, member_id: int) -> None:
        "ウェブサーバーから認証用の画像を削除します。"
        async with self.cog.session() as session:
            await session.post(
                f"{self.cog.bot.get_url()}{self.cog.BASE}image/delete",
                data=self.make_path(guild_id, member_id)
            )

    async def on_captcha(self, interaction: discord.Interaction):
        # 認証開始ボタンを押した人に対して返信をする。
        # もし既に画像がある場合はそれを使う。
        await interaction.response.send_message(
            embed=discord.Embed(
                title={
                    "ja": "画像認証", "en": "Image Captcha"
                },
                description={
                    "ja": "以下のボタンからみれる画像にある数字とあてはまる数字をメニューから選んでください。",
                    "en": "Select a number from the menu that matches the number in the image you can see from the button below."
                },
                color=self.cog.bot.Colors.normal
            ), view=SelectView(
                self, (
                    self.cog.queue[interaction.guild_id] \
                        [interaction.user.id][2].characters
                    if (
                        self.cog.queued(interaction.guild_id, interaction.user.id)
                        and hasattr(
                            self.cog.queue[interaction.guild_id] \
                                [interaction.user.id][2], "characters"
                        )
                    )
                    else await self.update_image(
                        interaction.guild_id, interaction.user.id
                    )
                ), "".join((
                    self.cog.bot.get_website_url(), self.BASE_PATH,
                    self.make_filename(interaction.guild_id, interaction.user.id)
                )), timeout=120
            ), ephemeral=True
        )
