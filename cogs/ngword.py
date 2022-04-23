# Free RT - NG Word

from __future__ import annotations

from discord.ext import commands
import discord

from util import RT, Table

from .log import log


class NGWords(Table):
    __allocation__ = "GuildID"
    words: list[str]


class DataManager:
    def __init__(self, bot: RT):
        self.data = NGWords(bot)

    def get(self, guild_id: int) -> list[str]:
        "NGワードのリストを取得します。"
        return self.data[guild_id].get("words", [])

    def _prepare(self, guild_id: int) -> None:
        # セーブデータの準備をします。
        if "words" not in self.data[guild_id]:
            self.data[guild_id].words = []

    def add(self, guild_id: int, word: str) -> None:
        "NGワードを追加します。"
        self._prepare(guild_id)
        assert word not in self.data[guild_id].words, "既に追加されています。"
        assert len(self.data[guild_id].words) < 50, "追加しすぎです。"
        self.data[guild_id].words.append(word)

    def remove(self, guild_id: int, word: str) -> None:
        "NGワードを削除します。"
        self._prepare(guild_id)
        assert word in self.data[guild_id].words, "そのNGワードはありません。"
        self.data[guild_id].words.remove(word)


class NgWord(commands.Cog, DataManager):
    def __init__(self, bot: RT):
        self.bot = bot
        super(commands.Cog, self).__init__(self.bot)

    HELP = ("ServerSafety", "ngword")

    @commands.group(
        aliases=["えぬじーわーど", "ng"], extras={
            "headding": {"ja": "NGワード", "en": "NG Word"},
            "parent": "ServerSafety"
        }
    )
    async def ngword(self, ctx):
        """!lang ja
        --------
        NGワード機能です。  
        `rf!ngword`で登録されているNGワードのリストを表示します。

        !lang en
        --------
        NG Word feature.
        Run `rf!ngword` to display ngwords registered."""
        if not ctx.invoked_subcommand:
            embed = discord.Embed(
                title={"ja": "NGワードリスト", "en": "NG Words"},
                description="* ".join(self.get(ctx.guild.id)),
                color=self.bot.colors["normal"]
            )
            await ctx.reply(embed=embed)

    @ngword.command(
        name="add", aliases=["あどど"], 
        extras={
            "headding": {
                "ja": "NGワードを追加します。",
                "en": "Remove NG Word"
            }
        }
    )
    @commands.has_guild_permissions(manage_messages=True)
    async def add_(self, ctx, *, words):
        """!lang ja
        --------
        NGワードを追加します。

        Parameters
        ----------
        words : NGワード(複数)
            改行を使うことで複数一括で登録できます。

        Examples
        --------
        `rf!ngword add あああ`  
        この場合、`あああ`を含むメッセージが削除されます。

        Notes
        -----
        チャンネルプラグインのログ出力機能のログチャンネルを作っている場合はそこにログが出力されます。

        !lang en
        --------
        Add NG words.

        Parameters
        ----------
        words : NG word(s)
            By using line feeds, you can register multiple items at once.

        Examples
        --------
        ```
        rf!ngword add ahoy
        Ahoy
        idiot
        Idiot
        ```

        Notes
        -----
        If you have created a log channel for the log output function of the channel plugin, the log will be output there."""
        await ctx.trigger_typing()
        for word in words.splitlines():
            self.add(ctx.guild.id, word)
        await ctx.reply("Ok")

    @ngword.command(
        name="remove", aliases=["りむーぶ", "rm", "delete", "del"],
        extras={
            "headding": {
                "ja": "NGワードを削除します。",
                "en": "Remove NG Word"
            }
        }
    )
    @commands.has_guild_permissions(manage_messages=True)
    async def remove_(self, ctx, *, words):
        """!lang ja
        --------
        NGワードを削除します。  
        NGワードを追加する際に実行したコマンドの逆です。これも改行で一括削除できます。

        Examples
        --------
        `rf!ngword remove あああ`  
        この場合`あああ`を含むメッセージが削除されないようになります。

        !lang en
        --------
        Remove the ng word(s).  
        This is the reverse of the command you executed when registering NG words.

        Examples
        --------
        `rf!ngword remove Badngword"""
        await ctx.trigger_typing()
        for word in words.splitlines():
            self.remove(ctx.guild.id, word)
        await ctx.reply("Ok")

    @commands.Cog.listener()
    @log(force=True)
    async def on_message(self, message: discord.Message):
        # 関係ないメッセージは無視する。
        if (not message.guild or message.author.id == self.bot.user.id
                or isinstance(message.author, discord.User)):
            return

        if not message.author.guild_permissions.administrator:
            for word in self.get(message.guild.id):
                if word in message.content:
                    await message.delete()
                    embed = discord.Embed(
                        title={"ja": "NGワードを削除しました。",
                               "en": "Removed the NG Word."},
                        color=self.bot.colors["unknown"]
                    )
                    embed.add_field(
                        name="Author",
                        value=f"{message.author.mention} ({message.author.id})",
                        inline=False
                    )
                    embed.add_field(name="Content", value=message.content)
                    return embed


def setup(bot):
    bot.add_cog(NgWord(bot))
