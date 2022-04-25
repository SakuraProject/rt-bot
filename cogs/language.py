# Free RT - Language

from typing import Literal, Union, List, Tuple

from discord.ext import commands
import discord

from util import RT

from aiofiles import open as async_open
from json import loads


class Language(commands.Cog):
    """# Language
    ## このコグの内容
    * 言語設定コマンド。
       - self.language
    * IDからそのIDになんの言語が設定されているかを取得する関数。
       - self.get
    * 言語データのリロード。
       - self.reload_language / self.update_language
    * send呼び出し時にもし実行者/サーバーが英語に設定しているなら、contentなどを言語データから英語のものに置き換えるようにsendを改造する。
       - self.dpy_injection

    ## このコグを読み込んでできること
    `channel.send("日本語", target=author.id)`や`message.reply("日本語")`とした時に自動で`data/replies.json`にある翻訳済み文字列に交換します。  
    もし一部環境などによっては変化する文字列がある場合は`data/replis.json`の方では`$$`にして、コードは`"$ここに変化する文字列$"`のようにすれば良いです。  
    もし翻訳済みに交換してほしくないテキストの場合は引数で`replace_language=False`とやればよいです。"""

    LANGUAGES = ("ja", "en")

    def __init__(self, bot: RT):
        self.bot = bot
        self.cache = {}
        self.guild_cache = {}

        self.bot.cogs["OnSend"].add_event(self._new_send, "on_send")
        self.bot.cogs["OnSend"].add_event(self._new_send, "on_webhook_send")
        self.bot.cogs["OnSend"].add_event(self._new_send, "on_webhook_message_edit")
        self.bot.cogs["OnSend"].add_event(self._new_send, "on_edit")

        self.pool = self.bot.mysql.pool
        self.bot.loop.create_task(self.on_ready())

        with open("data/replies.json",encoding="utf-8") as f:
            self.replies = loads(f.read())

    def cog_unload(self):
        for key in list(self.bot.cogs["OnSend"].events.keys()):
            for value in self.bot.cogs["OnSend"].events[key]:
                if value.__name__ == "_new_send":
                    self.bot.cogs["OnSend"].events[key].remove(value)

    def _get_ug(self, guild_id: int, user_id: int) -> str:
        lang = self.cache.get(guild_id)
        if lang is None or user_id in self.cache:
            return self.get(user_id)
        return lang

    async def _new_send(self, channel, *args, **kwargs):
        # 元のsendにつけたしをする関数。util.ext.on_sendを使う。
        # このsendが返信に使われたのなら返信先のメッセージの送信者(実行者)の言語設定を読み込む。
        lang = "ja"
        if isinstance(channel, discord.Message):
            if (reference := channel.reference) is not None:
                if reference.cached_message:
                    if channel.guild is None:
                        lang = self.get(reference.cached_message.author.id)
                    else:
                        lang = self._get_ug(channel.guild.id, reference.cached_message.author.id)
        elif isinstance(channel, discord.InteractionResponse):
            if channel._parent.guild_id is None:
                lang = self.get(channel._parent.user.id)
            else:
                lang = self._get_ug(channel._parent.guild_id, channel._parent.user.id)
        elif (reference := kwargs.get("reference")) is not None:
            if reference.guild is None:
                lang = self.get(reference.author.id)
            else:
                lang = self._get_ug(reference.guild.id, reference.author.id)
        if (target := kwargs.pop("target", False)):
            if not isinstance(target, int):
                target = target.id
            lang = self.cache.get(target) or self.get(target)

        if not kwargs.pop("replace_language", True):
            # もし言語データ交換するなと引数から指定されたならデフォルトのjaにする。
            lang = "ja"
        # contentなどの文字列が言語データにないか検索をする。
        if kwargs.get("content", False):
            kwargs["content"] = self.get_text(kwargs["content"], lang)
        if args and not isinstance(args[0], int):
            args = (self.get_text(args[0], lang),)
        if kwargs.get("embed", False):
            kwargs["embed"] = self.get_text(kwargs["embed"], lang)
        if "embeds" in kwargs:
            kwargs["embeds"] = [self.get_text(embed, lang)
                                for embed in kwargs.get("embeds", [])]

        return args, kwargs

    def _extract_question(self, text: str, parse_character: str = "$") -> Tuple[List[str], List[str]]:
        # 渡された文字列の中にある`$xxx$`のxxxのやところを
        now, now_target, results, other = "", False, [], ""

        for char in text:
            if char == parse_character:
                if now_target:
                    results.append(now)
                    now_target = False
                    now = ""
                else:
                    now_target = True
            if now_target and char != parse_character:
                now += char
            else:
                other += char

        return results, other

    def _get_reply(self, text: Union[str, dict], lang: Literal["ja", "en"]) -> str:
        result = ""
        if text:
            if isinstance(text, str) and text[0] != "{":
                # 指定された文字を指定された言語で交換します。
                # 言語データから文字列を取得する。
                result = self.replies.get(text, {}).get(lang, text)
            else:
                if isinstance(text, str) and text[0] == "{" and text[-1] == "}":
                    try:
                        result = eval(text)
                    except ValueError:
                        result = str(text)
                    else:
                        result = result.get(lang, result.get("ja", text))
                elif isinstance(text, dict):
                    result = text.get(lang, text["ja"])
                else:
                    result = str(text)

        return result

    def _replace_embed(self, embed: discord.Embed, lang: Literal["ja", "en"]) -> discord.Embed:
        # Embedを指定された言語コードで交換します。
        # タイトルとディスクリプションを交換する。
        for n in ("title", "description"):
            if getattr(embed, n) is not discord.Embed.Empty:
                setattr(embed, n, self._get_reply(getattr(embed, n), lang))
        # Embedにあるフィールドの文字列を交換する。
        for index in range(len(embed.fields)):
            embed.set_field_at(
                index, name=self._get_reply(embed.fields[index].name, lang),
                value=self._get_reply(embed.fields[index].value, lang),
                inline=embed.fields[index].inline
            )
        # Embedのフッターを交換する。
        if embed.footer:
            if embed.footer.text is not discord.Embed.Empty:
                embed.set_footer(text=self._get_reply(embed.footer.text, lang),
                                 icon_url=embed.footer.icon_url)
        return embed

    def get_text(self, text: Union[str, discord.Embed],
                 target: Union[int, Literal["ja", "en"]]) -> str:
        """渡された言語コードに対応する文字列に渡された文字列を交換します。  
        また言語コードの代わりにユーザーIDを渡すことができます。  
        ユーザーIDを渡した場合はそのユーザーIDに設定されている言語コードが使用されます。  
        またまた文字列の代わりにdiscord.Embedなどを渡すこともできます。

        Parameters
        ----------
        text : Union[str, discord.Embed]
            交換したい文字列です。
        target : Union[int, Literal["ja", "en"]]
            対象のIDまたは言語コードです。"""
        # この関数はself._get_replyとself._replace_embedを合成したようなものです。
        if isinstance(target, int):
            target = self.get(target)
        if isinstance(text, (str, dict)):
            return self._get_reply(text, target)
        elif isinstance(text, discord.Embed):
            return self._replace_embed(text, target)

    async def update_language(self) -> None:
        # 言語データを更新します。
        async with async_open("data/replies.json") as f:
            self.replies = loads(await f.read())

    async def update_cache(self, cursor):
        # キャッシュを更新します。
        await cursor.execute("SELECT * FROM language;")
        for row in await cursor.fetchall():
            if row:
                self.cache[row[0]] = row[1]

    @commands.Cog.listener()
    async def on_update_api(self):
        async with self.bot.session.post(
            f"{self.bot.get_url()}/api/account/language", json=self.cache
        ) as r:
            self.bot.print("[LanguageUpdate]", await r.text())

    async def on_ready(self):
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    "CREATE TABLE IF NOT EXISTS language (id BIGINT, language TEXT);"
                )
                # キャッシュを更新しておく。
                await self.update_cache(cursor)

    def get(self, ugid: int) -> Literal["ja", "en"]:
        """渡されたIDになんの言語が設定されているか取得できます。  
        Bot起動後でないと正しい情報を取得することができないので注意してください。

        Parameters
        ----------
        ugid : int
            ユーザーIDまたはサーバーIDです。

        Returns
        -------
        Literal["ja", "en"] : 言語コード。"""
        return self.cache.get(ugid, "ja")

    @commands.command(
        aliases=["lang"],
        extras={
            "headding": {
                "ja": "Change language setting.",
                "en": "言語設定を変更します。"
            },
            "parent": "RT"
        }
    )
    async def language(self, ctx, language: Literal["ja", "en"], mode: Literal["server", "user"] = "user"):
        """!lang ja
        --------
        Change the language setting for RT.

        Parameters
        ----------
        language : Language code, `ja` or `en`
            Code for the language to change.  
            You can use the Japanese `ja` or the English `en`.
        mode : server or user, default user
            You can either set it for the entire server or for a user.  
            If you set it to server-wide and set it to English, it will be set to English even if no one on that server has it set to English.

        Raises
        ------
        ValueError : Occurs if an invalid language code is inserted.

        Examples
        --------
        `rf!language en` to set your language to English.
        Set the language of the entire server to English, as executed by `rf!language en server`.

        !lang en
        --------
        RTの言語設定を変更します。

        Parameters
        ----------
        language : 言語コード, `ja`または`en`
            変更対象の言語コードです。  
            現在は日本語である`ja`と英語である`en`に対応しています。
        mode : serverまたはuser、デフォルトはuser
            サーバー全体に適応するか自分だけ変更するかです。

        Raises
        ------
        ValueError : もし無効な言語コードが入れられた場合発生します。

        Examples
        --------
        `rf!language ja`で言語を日本語に変更できます。"""
        # 言語コードが使えない場合はValueErrorを発生する。
        if language not in self.LANGUAGES:
            code = "invalid language code is inserted. 無効な言語コードです。"
            return await ctx.reply(code)

        # 返信内容と変更内容を用意する。
        color = self.bot.colors["normal"]
        title, description = "Ok", discord.Embed.Empty
        await ctx.trigger_typing()

        # データベースに変更内容を書き込む。
        ugid = ctx.author.id if mode == "user" else ctx.guild.id
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    "SELECT id FROM language WHERE id = %s;",
                    (ugid,)
                )
                if await cursor.fetchone():
                    await cursor.execute(
                        "UPDATE language SET language = %s WHERE id = %s;",
                        (language, ugid)
                    )
                else:
                    await cursor.execute(
                        "INSERT INTO language VALUES (%s, %s);",
                        (ugid, language)
                    )
                self.cache[ugid] = language

        # 返信をする。
        await ctx.reply("Ok")


def setup(bot):
    bot.add_cog(Language(bot))
