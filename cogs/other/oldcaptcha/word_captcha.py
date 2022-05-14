# Free RT - Captcha Word Manager

from typing import TYPE_CHECKING, Dict, Tuple

from discord.ext import commands
import discord

from time import time

if TYPE_CHECKING:
    from .__init__ import Captcha


class WordCaptcha(commands.Cog):
    def __init__(self, captcha_cog: "Captcha"):
        self.cog = captcha_cog
        self.queue: Dict[str, Tuple[Tuple[int, str], float]] = {}
        self.cog.bot.add_listener(self.on_message, "on_message")

    async def captcha(
        self, channel: discord.TextChannel, member: discord.Member
    ) -> None:
        await channel.send(
            {"ja": f"{member.mention}, 合言葉を入力してください。"
                   "\n放置すると無効になります。",
             "en": f"{member.mention}, Please type password."
                   "\nIf you leave it, it will become invalid."},
            target=member.id
        )
        row = await self.cog.load(channel.guild.id)
        self.queue[f"{channel.id}-{member.id}"] = ((row[3], row[4]), time())

    async def on_message(self, message: discord.Message) -> None:
        if (row := self.queue.get(
                f"{message.channel.id}-{message.author.id}", (None,)))[0]:
            row = row[0]
            if message.content == row[1]:
                role = message.guild.get_role(row[0])
                if role:
                    try:
                        await message.author.add_roles(role)
                    except Exception as e:
                        await message.channel.send(
                            {"ja": (f"{message.author.mention}, 認証に失敗しました。\n"
                                    "付与する役職がRTの役職より下にあるか確認してください。\n"
                                    f"エラーコード：{e}"),
                             "en": f"{message.author.mention}, Failed, make sure that the role position below the RT role position."},
                        )
                    else:
                        await message.channel.send(
                            {"ja": f"{message.author.mention}, 認証に成功しました。",
                             "en": f"{message.author.mention}, Success!"}
                        )
                        try:
                            await message.delete()
                        except (discord.HTTPException, discord.Forbidden):
                            pass
                        finally:
                            self.cog.remove_cache(message.author)
                            del self.queue[f"{message.channel.id}-{message.author.id}"]
                else:
                    await message.channel.send(
                        {"ja": f"{message.author.mention}, 役職が見つからないため認証に失敗しました。",
                         "en": f"{message.author.mention}, Failed, I couldn't find the role to add you."}
                    )
            else:
                await message.channel.send(
                    {"ja": f"{message.author.mention}, 合言葉が違います。",
                     "en": f"{message.author.mention}, That password is wrong."}
                )
