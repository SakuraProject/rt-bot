# Free RT - Google Translator

from discord.ext import commands
import discord

from jishaku.functools import executor_function
from asyncio import sleep
import deep_translator

from util import RT


CHP_HELP = {
    "ja": ("翻訳専用チャンネル機能。",
           """# 翻訳チャンネルプラグイン - translate
これは`rf>translate <翻訳先言語コード>`をチャンネルのトピックに入れることで翻訳専用チャンネルにすることのできる機能です。  
例：`rf>translate ja` (これをトピックに入れたチャンネルに送信したメッセージは全て日本語に翻訳されます。)  

### 言語コード例
```
日本語 ja
英語　 en
自動　 auto
```
他は調べれば出るので`言語名 言語コード`とかで調べてください。

### エイリアス
trans, ほんやく, 翻訳

### これもあるよ
翻訳コマンドである`translate`で個人カテゴリーにあります。"""),
    "en": ("Dedicated translation channel function", """# translation channel plugin - translate
This is a feature that allows you to make a channel dedicated to translation by putting `rf>translate <language code to translate to>` in the channel topic.  
Example: `rf>translate ja` (all messages sent to a channel with this in the topic will be translated into Japanese).  

### Language code example
```
Japanese `ja`  
English  `en`
```
Other codes can be found by looking up `<language name> code` or something like that.

### Alias
trans

### Also see
It's in the personal category with the `translate` command.""")
}


class Translator(commands.Cog):
    def __init__(self, bot: RT):
        self.bot = bot

    @executor_function
    def translate(self, text: str, target: str) -> str:
        return deep_translator.GoogleTranslator(target=target).translate(text)

    async def cog_load(self):
        # ヘルプにチャンネルプラグイン版翻訳を追加するだけ。
        await sleep(1.5)
        for lang in CHP_HELP:
            self.bot.cogs["DocHelp"].add_help(
                "ChannelPlugin", "TranslateChannel",
                lang, *CHP_HELP[lang]
            )

    @commands.command(
        name="translate", aliases=["trans", "ほんやく", "翻訳"], extras={
            "headding": {"ja": "翻訳をします。", "en": "This can do translate."},
            "parent": "Individual"
        }
    )
    @commands.cooldown(1, 5, commands.BucketType.user)
    async def translate_(self, ctx, lang, *, content):
        """!lang ja
        --------
        翻訳をします。

        Parameters
        ----------
        lang : 言語コード
            どの言語に翻訳するかの言語コードです。  
            例えば日本語にしたい場合は`ja`で、英語にしたい場合は`en`です。  
            `auto`とすると自動で翻訳先を英語または日本語に設定します。
        content : str
            翻訳する内容です。

        Examples
        --------
        `rt!translate ja I wanna be the guy!`
        RT：男になりたい！

        Aliases
        -------
        trans, ほんやく, 翻訳

        See Also
        --------
        translate(チャンネルプラグイン) : 翻訳専用チャンネル機能。

        !lang en
        --------
        This can do translate.

        Parameters
        ----------
        lang : language code
            The language code for which language to translate.
            If you want use japanese you do `ja` and If you want to use English you do `en`.
        content : str
            Translate content

        Examples
        --------
        `rt!translate ja I wanna be the guy!`
        RT：男になりたい！

        Aliases
        -------
        trans

        See Also
        --------
        translate(channel plugin) : Only for translate channel."""
        await ctx.typing()

        if lang == "auto":
            # もし自動で翻訳先を判別するなら英文字が多いなら日本語にしてそれ以外は英語にする。
            lang = "ja" if (
                sum(64 < ord(char) < 123 for char in content)
                >= len(content) / 2
            ) else "en"

        try:
            await ctx.reply(
                embed=discord.Embed(
                    title={"ja": "翻訳結果",
                           "en": "translate result"},
                    description=await self.translate(content, lang),
                    color=self.bot.colors["normal"]
                ).set_footer(
                    text="Powered by Google Translate",
                    icon_url="http://tasuren.syanari.com/RT/GoogleTranslate.png"
                )
            )
        except deep_translator.exceptions.LanguageNotSupportedException:
            await ctx.reply("その言語は対応していません。")

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if isinstance(message.channel, discord.Thread):
            return
        if ((message.author.bot and not (
            message.author.discriminator == "0000" and " #" in message.author.name
        )) or not message.guild or not message.channel.topic):
            return

        for line in message.channel.topic.splitlines():
            if line.startswith(("rf>translate", "rf>tran", "rf>翻訳", "rf>ほんやく")):
                if 1 < len((splited := line.split())):
                    try:
                        message.content = f"{splited[1]} {message.content}"
                        await self.translate_.invoke(
                            ctx := await self.bot.get_context(message)
                        )
                    except Exception as e:
                        self.bot.dispatch("command_error", ctx, e)
                break


async def setup(bot):
    await bot.add_cog(Translator(bot))
