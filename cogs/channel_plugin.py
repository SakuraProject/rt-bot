# Free RT - Channel Plugin

from discord.ext import commands
import discord

from util import RT

from inspect import cleandoc
from asyncio import sleep
from re import findall


HELPS = {
    "ChannelPluginGeneral": {
        "ja": (
            "画像, URLの自動スポイラー", cleandoc("""# 画像, URLの自動スポイラー
            `rf>asp`をチャンネルトピックに入れることでタイトル通り画像とURLにスポイラーがついてメッセージが再送信されるようになります。  
            なお、`rf>asp`の他に単語を空白で分けて右に書けばその言葉もスポイラーするようになります。

            ### 警告
            これを使うとスポイラーがついた際に再送信するのでメッセージを編集することができなくなります。

            ### メモ
            `rf>ce`をチャンネルトピックに入れることで全部のメッセージが再送信されて編集できなくなります。  
            (他の人のメッセージを削除する権限がある人はメッセージの削除が可能です。)  
            失言を許さないサーバーオーナーは設定してみましょう。""")
        ),
        "en": (
            "Image, URL Auto Spoiler", cleandoc("""# Automatic spoiler for images, URLs
            This will resend the message with spoilers for images and URLs by putting `rf>asp` in the channel topic, as the title says.  
            In addition to `rf>asp`, you can also spoil words by separating them with spaces and writing them on the right.

            ### Warning
            If you use this, the message will be resent when it is spoiled and you will not be able to edit it.

            ### Notes.
            If you put `rf>ce` in a channel topic, all messages will be resent and you will not be able to edit them.  
            (You can delete messages if you are not authorized to do so and can delete other people's messages.""")
        )
    },
    "ChannelKick": {
        "ja": (
            "チャンネルキック", cleandoc("""# チャンネルキック
            特定の言葉がメッセージに含まれていないとキックされるチャンネルにします。
            `rf>kick <空白で分けたメッセージに必要な言葉>`をチャンネルのトピックに入れてください。""")
        ),
        "en": (
            "ChannelKick", cleandoc("""# Channel kick
            To make a channel that will be kicked if certain words are not included in the message.
            Put `rf>kick <word required in message separated by spaces>` in the channel topic.""")
        )
    }
}
class RemoveButton(discord.ui.View):
    def __init__(self, user_id: int):
        self.user_id = user_id
        super().__init__()

    @discord.ui.button(label="削除ボタン", style=discord.ButtonStyle.danger, emoji="🗑")
    async def remove_button(self, _, interaction: discord.Interaction):
        if self.user_id == interaction.user.id:
            await interaction.response.send_message(
                {
                    "ja": "削除します。", "en": "I'll delete this message."
                }, ephemeral=True
            )
            await interaction.message.delete(delay=2.35)
        else:
            await interaction.response.send_message(
                {
                    "ja": "あなたはこのメッセージを削除できません。",
                    "en": "You can't delete this message."
                }, ephemeral=True
            )


class ChannelPluginGeneral(commands.Cog):

    URL_PATTERN = "https?://[\\w/:%#\\$&\\?\\(\\)~\\.=\\+\\-]+"

    def __init__(self, bot: RT):
        self.bot = bot
        self.bot.loop.create_task(self.on_command_added())

    async def on_command_added(self):
        await sleep(1.5)
        for command_name in HELPS:
            for lang in HELPS[command_name]:
                self.bot.cogs["DocHelp"].add_help(
                    "ChannelPlugin", command_name,
                    lang, HELPS[command_name][lang][0],
                    HELPS[command_name][lang][1]
                )

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if isinstance(message.channel, discord.Thread):
            return
        if not message.guild or message.author.discriminator == "0000":
            return

        if message.channel.topic:
            for cmd in message.channel.topic.splitlines():
                if cmd.startswith("rf>asp"):
                    # Auto Spoiler
                    content = message.clean_content

                    # 添付ファイルをスポイラーにする。
                    new = []
                    for attachment in message.attachments:
                        attachment.filename = f"SPOILER_{attachment.filename}"
                        new.append(await attachment.to_file())
                    # urlをスポイラーにする。
                    for url in findall(self.URL_PATTERN, content):
                        content = content.replace(url, f"||{url}||", 1)
                    # もしスポイラーワードが設定されているならそれもスポイラーにする。
                    view = None
                    for word in cmd.split()[1:]:
                        content = content.replace(word, f"||{word}||")
                    # Embedに画像が設定されているなら外してスポイラーを付けた画像URLをフィールドに入れて追加する。
                    e = False
                    for index in range(len(message.embeds)):
                        if message.embeds[index].image.url is not message.embeds[index].Empty:
                            message.embeds[index].add_field(
                                name="この埋め込みに設定されている画像",
                                value=f"||{message.embeds[index].image.url}||"
                            )
                            message.embeds[index].set_image(url=message.embeds[index].Empty)
                            e = True

                    # 送信し直す。
                    if ((message.content and message.clean_content != content)
                            or message.attachments or (message.embeds and e)):
                        # 送信しなおす。
                        if message.reference:
                            content = f"返信先：{message.reference.jump_url}\n{content}"
                        await message.channel.webhook_send(
                            content, files=new, embeds=message.embeds,
                            username=message.author.display_name + " RT's Auto Spoiler",
                            avatar_url=message.author.avatar.url,
                            view=RemoveButton(message.author.id)
                        )
                        try:
                            await message.delete()
                        except (discord.NotFound, discord.Forbidden):
                            pass
                elif cmd.startswith("rf>ce"):
                    # Can't Edit
                    await message.channel.webhook_send(
                        message.clean_content, files=[
                            await at.to_file()
                            for at in message.attachments
                        ], username=message.author.display_name,
                        avatar_url=message.author.avatar.url
                    )
                    await message.delete()
                elif cmd.startswith("rf>embed"):
                    # Auto Embed
                    await self.bot.cogs["ServerTool"].embed(
                        await self.bot.get_context(message), "null",
                        content=message.content
                    )
                    await message.delete()
                elif cmd.startswith("rf>kick "):
                    # Kick
                    for word in cmd.split()[1:]:
                        if word not in message.content:
                            try:
                                await message.author.kick(
                                    reason=f"[ChannelPlugin]{word}がメッセージになかったため。"
                                )
                            except discord.Forbidden:
                                await message.reply(
                                    "必要なメッセージがないのでキックしようとしましたが権限がないのでできませんでした。"
                                )
                            finally:
                                break


def setup(bot):
    bot.add_cog(ChannelPluginGeneral(bot))
