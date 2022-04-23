# Free RT - Free Channel

from typing import Literal

from discord.ext import commands
import discord

from util import RT, settings

from asyncio import sleep


async def freechannel(ctx: commands.Context) -> bool:
    # フリーチャンネルか確かめるためのコマンドに付けるデコレータです。
    if isinstance(ctx.channel, discord.TextChannel):
        return (ctx.channel.topic and "RTフリーチャンネル" in ctx.channel.topic
                and str(ctx.author.id) in ctx.channel.topic
                and "作成者" in ctx.channel.topic and ctx.channel.category)
    else:
        return ctx.category is not None


class FreeChannel(commands.Cog):
    def __init__(self, bot: RT):
        self.bot = bot
        self.cooldown = {
            "make": {},
            "remove": {},
            "rename": {}
        }

    @commands.group(
        extras={
            "headding": {
                "ja": "実行したチャンネルをフリーチャンネル作成専用のチャンネルにします。",
                "en": "Make the executed channel a dedicated channel for free channel creation."
            },
            "parent": "ServerPanel"
        },
        name="freechannel",
        aliases=["fc", "FreeChannel", "自由チャンネル", "114514チャンネル"]
    )
    async def freechannel_(self, ctx):
        """!lang ja
        --------
        フリーチャンネルのコマンドです。

        !lang en
        --------
        Free Channel (like thread)"""
        if not ctx.invoked_subcommand:
            await ctx.send(
                {"ja": f"{ctx.author.mention}, 使用方法が違います。",
                 "en": f"{ctx.author.mention}, ..."},
                delete_after=5, target=ctx.author.id
            )

    @freechannel_.command(aliases=["add", "rg"])
    @commands.cooldown(1, 300, commands.BucketType.user)
    @commands.has_permissions(manage_channels=True)
    async def register(self, ctx, max_channel: int = 4, lang: Literal["ja", "en"] = "ja"):
        """!lang ja
        --------
        実行したチャンネルをフリーチャンネル作成専用のチャンネルにします。  
        このコマンドを実行したチャンネルに`text:チャンネル名`と送るとチャンネルが作られる感じです。  
        ボイスチャンネルの場合は`voice:チャンネル名`を送ると作成されます。  

        Warnings
        --------
        このコマンドを実行できるのは`チャンネル管理`権限を持っている人のみです。  
        また、作成されるフリーチャンネルはこのチャンネルのカテゴリー内です。  
        よってこのコマンドはカテゴリーの中にあるチャンネルでのみ実行可能です。

        Parameters
        ----------
        max_channel : int, default 4
            個人個人が作れる最大チャンネル数です。  
            入力しない場合は4となります。
        lang : str, default ja
            フリーチャンネルの説明のパネルを日本語か英語どっちで表示するかです。  
            入力しない場合は`ja`で日本語になっており英語にしたい場合は`en`にしてください。

        Aliases
        -------
        `rg`

        !lang en
        --------
        This will make the channel you run into a dedicated channel for creating free channels.  
        If you send `text:channel name` to the channel you ran this command on, it will create the channel.  
        For a voice channel, you can use `voice:channel name`.  

        Warnings
        --------
        This command can only be executed by someone with `channel management` privileges.  
        Also, the free channel created will be in the category of the channel you run this command on.  
        Therefore, this command can only be executed on channels that are in the category.

        Parameters
        ----------
        max_channel : int, default 4
            The maximum number of channels an individual can create.  
            If not entered, the value will be 4.
        lang : str, default ja
            Whether to display the free channel description panel in Japanese or English.  
            If you don't enter it, it is set to `en` if you want it to be in English."""
        if ctx.channel.category is None:
            await ctx.reply(
                {"ja": "カテゴリーのあるチャンネルでのみこのコマンドは実行可能です。",
                 "en": "You can run this command on only channel that have category."}
            )
            return
        if (ctx.channel.topic and "RTフリーチャンネル" in ctx.channel.topic
                and "作成者" not in ctx.channel.topic):
            await ctx.send(
                {"ja": f"既にフリーチャンネル作成用チャンネルとなっています。",
                 "en": f"It is already a channel for creating free channels."},
                delete_after=5, target=ctx.author.id
            )
            return

        title = {"ja": "フリーチャンネル", "en": "Free Channel"}
        description = {
            "ja": """好きなチャンネル名を送信することでそのチャンネルを作成することができます。
**#** 作成方法
テキストチャンネル：このチャンネルで`text チャンネル名`
ボイスチャンネル：このチャンネルで`voice チャンネル名`
**#** 改名方法
テキストチャンネル：そのフリーチャンネルで`rf!rename 改名後の名前`
ボイスチャンネル：適当なチャンネルで`rf!rename ボイスチャンネル名 改名後の名前`
※作成されるボイスチャンネルの名前には作成した人のIDが含まれますが、このIDは改名時にチャンネル名に入れる必要はないです。
**#** 削除方法
テキストチャンネル：そのフリーチャンネルで`rf!remove`
ボイスチャンネル：適当なチャンネルで`rf!remove ボイスチャンネル名`
※作成されるボイスチャンネルの名前には作成した人のIDが含まれますが、このIDは削除時にチャンネル名に入れる必要はないです。""",
            "en": """You can create a channel by sending the name of the channel you want.
**#** How to create
Text channel: `text channel name` in this channel
Voice channel: `voice channel name` in this channel
**#** How to rename
Text channel: `rf!rename renamed name` in that free channel
Voice channel: On a suitable channel, use `rf!rename voice channel name after renaming`.
The name of the created voice channel will include the ID of the person who created it, but this ID does not need to be included in the channel name when renaming it.
**#** How to delete
Text channel: `rf!remove` on that free channel
Voice channel: `rf!remove voice channel name` on an appropriate channel.
The name of the created voice channel will include the ID of the person who created it, but this ID does not need to be included in the channel name when removing it."""
        }

        footer = {"ja": f"一人{max_channel}個までチャンネルを作成可能です。",
                  "en": f"{max_channel}..."}
        embed = discord.Embed(
            title=title[lang],
            description=description[lang],
            color=self.bot.colors["normal"]
        )
        embed.set_footer(text=footer[lang])

        await ctx.webhook_send(
            username=ctx.author.display_name,
            avatar_url=getattr(ctx.author.avatar, "url", ""),
            embed=embed
        )
        await sleep(0.4)
        await ctx.channel.edit(
            topic=(f"RTフリーチャンネル\n作成可能チャンネル数：{max_channel}"
                   + "\nこのトピックは消さないでください。/ 英語版をここに")
        )

    @freechannel_.command(name="remove")
    @commands.cooldown(1, 300, commands.BucketType.user)
    @commands.has_permissions(manage_channels=True)
    async def remove_(self, ctx):
        """!lang ja
        --------
        実行したチャンネルがフリーチャンネル作成用チャンネルの場合、その設定を解除します。
        
        !lang en
        --------
        Remove settings of freechannel registration channel if the channel was it.
        """
        if (ctx.channel.topic and "RTフリーチャンネル" in ctx.channel.topic
                and "作成者" not in ctx.channel.topic):
            await ctx.channel.edit(topic=None)
            await ctx.send(
                {"ja": f"{ctx.author.mention}, フリーチャンネル作成用チャンネルを無効化しました。",
                 "en": f"{ctx.author.mention}, ..."},
                target=ctx.author.id
            )
        else:
            await ctx.reply(
                {"ja": "ここはフリーチャンネル作成用チャンネルではありません。",
                 "en": "..."}
            )

    @commands.command()
    @commands.check(freechannel)
    @commands.cooldown(1, 15, commands.BucketType.user)
    async def remove(self, ctx, name=None):
        await ctx.trigger_typing()
        if name is None:
            await ctx.channel.delete()
        else:
            for channel in ctx.channel.category.voice_channels:
                if channel.name == f"{name}-{ctx.author.id}":
                    await channel.delete()
                    await ctx.reply(
                        {"ja": "チャンネルを削除しました。",
                        "en": "..."}
                    )
                    break
            else:
                await ctx.reply(
                    {"ja": "チャンネルが見つかりませんでした。",
                     "en": "..."}
                )

    @commands.command()
    @commands.check(freechannel)
    @commands.cooldown(1, 300, commands.BucketType.user)
    async def rename(self, ctx, name: str, *, after: str = None):
        await ctx.trigger_typing()
        if after is None:
            await ctx.channel.edit(name=name)
        else:
            for channel in ctx.channel.category.voice_channels:
                if channel.name == f"{name}-{ctx.author.id}":
                    await channel.edit(name=f"{after}-{ctx.author.id}")
                    break
            else:
                await ctx.reply(
                    {"ja": "チャンネルが見つかりませんでした。",
                     "en": "..."}
                )
        await ctx.reply(
            {"ja": "チャンネル名を変更しました。",
             "en": "..."}
        )

    @commands.Cog.listener()
    async def on_message(self, message):
        if (not message.guild or not hasattr(message.channel, "topic")
                or not message.content or not message.channel.topic):
            return

        topic = message.channel.topic if message.channel.topic else ""
        if ("RTフリーチャンネル" in topic and "作成者" not in topic
                and message.channel.category):
            # フリーチャンネルでのユーザーへの返信の場合は
            if not (message.author.id == self.bot.user.id
                    and ">," in message.content):
                await message.delete()

            # もしフリーチャンネルでのユーザーへのRTの返信じゃないそれかBotならコマンドの実行はさせない。
            if message.author.bot or not message.content.startswith(("text", "voice")):
                return
            else:
                await message.channel.trigger_typing()

            # 作成に必要な情報を変数に入れる。max_channelは最大チャンネル数。
            max_channel = int(topic[22:topic.find("\nこ")])
            user_id = str(message.author.id)
            now = {
                "text": [channel
                         for channel in message.channel.category.text_channels
                         if channel.topic and user_id in channel.topic],
                "voice": [channel
                          for channel in message.channel.category.voice_channels
                          if channel.name.endswith("-" + user_id)]
            }

            if message.content.startswith(("text ", "voice ")):
                # チャンネルの作成。
                mode = "text" if message.content[0] == "t" else "voice"

                if len(now[mode]) >= max_channel:
                    await message.channel.send(
                        {"ja": f"{message.author.mention}, あなたはチャンネルをこれ以上作れません。",
                         "en": f"{message.author.mention}, You can't make channels any more."},
                         delete_after=5, target=message.author.id
                    )
                    return 

                if mode == "text":
                    coro = message.channel.category.create_text_channel(
                        message.content[5:], topic=f"RTフリーチャンネル, 作成者：{user_id}"
                    )
                    mode = ("テキスト", "text")
                else:
                    coro = message.channel.category.create_voice_channel(
                        "".join((message.content[6:], "-", user_id))
                    )
                    mode = ("ボイス", "voice")

                await coro
                await message.channel.send(
                    {"ja": f"{message.author.mention}, {mode[0]}チャンネルを作成しました。",
                     "en": f"{message.author.mention}, Complated making {mode[1]} channel."},
                    delete_after=5, target=message.author.id
                )


def setup(bot):
    bot.add_cog(FreeChannel(bot))
