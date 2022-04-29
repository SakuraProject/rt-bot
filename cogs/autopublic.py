# Free RT - Auto Public

from discord.ext import commands


CHP_HELP = {
    "ja": ("メッセージ自動公開機能。",
           """# メッセージ自動公開プラグイン - autopublic
これは`rf>autopublic <optionでcheck>`をニュースチャンネルのトピックに入れることで自動的にメッセージを公開してくれる機能です。  
例：`rf>autopublic` (これをトピックに入れたチャンネルに送信したメッセージは全てメッセージを公開してくれます)
例: `rf>autopublic check` (これをトピックに入れたチャンネルに送信したメッセージは全てメッセージを公開してくれますが、公開するとメッセージにチェックが入ります)
"""),
    "en": ("message auto public.",
           """# # Message autopublishing plugin - autopublic
This is a feature that allows you to automatically publish messages by putting `rf>autopublic <check with option>` in the topic of a news channel.  
Example: `rf>autopublic` (any message sent to a channel with this in the topic will make the message public)
Example: `rf>autopublic check` (any message sent to a channel with this in the topic will make the message public, but the message will be checked when it is made public)
""")
}


class AutoPublic(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.Cog.listener()
    async def on_help_reload(self):
        for lang in CHP_HELP:
            self.bot.cogs["DocHelp"].add_help(
                "ChannelPlugin", "AutoPublic",
                lang, *CHP_HELP[lang]
            )

    @commands.Cog.listener()
    async def on_message(self, message):
        if not hasattr(message.channel, "topic"):
            return
        if not message.guild or message.author.bot or not message.channel.topic:
            return
        for line in message.channel.topic.splitlines():
            if line.startswith("rf>autopublic"):
                await message.publish()
                if len(line.split()) >= 1:
                    option = line.split()[0]
                    if option == "check":
                        await message.add_reaction("✅")


def setup(bot):
    bot.add_cog(AutoPublic(bot))
