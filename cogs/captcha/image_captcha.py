# RT - Captcha Image Manager

from jishaku.functools import executor_function
from captcha.image import ImageCaptcha
from typing import Type, Dict, Tuple
from aiofiles.os import remove
from random import randint
from os import listdir
from time import time

from discord.ext import commands
import discord


class ImageCaptcha(ImageCaptcha):

    PASSWORD_LENGTH = 5

    def __init__(
            self, captcha_cog,
            font_path: str = "data/captcha/SourceHanSans-Normal.otf"
            ):
        self.cog = captcha_cog
        super().__init__(fonts=[font_path])
        self.queue: Dict[str, Tuple[str, float]] = {}
        self.cog.bot.add_listener(self.on_message, "on_message")
        self.cog.bot.add_listener(self.on_close, "on_close")

    @executor_function
    def create_image(
            self, path: str, characters: str = "".join(
                str(randint(0, 9))
                for _ in range(PASSWORD_LENGTH))
            ) -> str:
        self.write(characters, path)
        return characters

    async def captcha(self, channel: discord.TextChannel,
                      member: discord.Member) -> None:
        name = f"{channel.id}-{member.id}"
        path = f"data/captcha/{name}.png"
        self.queue[name] = (await self.create_image(path), time())
        await channel.send(
            {"ja": f"{member.mention}, 画像にある数字を入力してください。",
             "en": f"{member.mention}, Please, type number on the picture."},
            target=member.id, file=discord.File(path)
        )
        await remove(path)

    async def on_message(self, message: discord.Message) -> None:
        name = f"{message.channel.id}-{message.author.id}"
        if name in self.queue and len(message.content) == self.PASSWORD_LENGTH:
            if message.content == self.queue[name][0]:
                row = await self.cog.load(message.guild.id)
                role = message.guild.get_role(row[3])

                if role:
                    try:
                        await message.author.add_roles(role)
                    except Exception as e:
                        await message.reply(
                            {"ja": ("役職を付与することができませんでした。\n"
                                    "付与する役職の位置がRTより下にあるか確認してください。\n"
                                    f"エラーコード：`{e}`"),
                             "en": "..."}
                        )
                    else:
                        await message.reply(
                            {"ja": "認証に成功しました。",
                             "en": "..."}
                        )
                else:
                    await message.reply(
                        {"ja": "設定されている役職が見つからないため認証に失敗しました。",
                         "en": "..."}
                    )
            else:
                await message.reply(
                    {"ja": "認証に失敗しました。\n番号があっているか確認してください。",
                     "en": "..."}
                )

    async def on_close(self, _):
        # Bot終了時にもし画像認証の画像が残っているのなら削除しておく。
        for name in listdir("data/captcha"):
            if name.endswith(".png"):
                await remove(f"data/captcha/{name}")