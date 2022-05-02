# Free RT - Reprypt

from discord.ext import commands
import discord

from time import time
import reprypt
import sanic


class Reprypt(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.rate = {}

    @commands.group(
        extras={
            "headding": {"ja": "Repryptを使用して文章を暗号化/復号化します。",
                         "en": "Encryption/Decryption by Reprypt."},
            "parent": "Individual"
        },
        name="reprypt"
    )
    async def reprypt_(self, ctx):
        """!lang ja
        --------
        Repryptを使用して文章を暗号化/復号化します。

        !lang en
        --------
        Encryption/Decryption by Reprypt."""
        if not ctx.invoked_subcommand:
            await ctx.reply(
                {"ja": "使い方が違います。",
                 "en": "..."}
            )

    @reprypt_.command(aliases=["en"])
    async def encrypt(self, ctx, key, *, content):
        """!lang ja
        --------
        指定された文章を暗号化します。

        Parameters
        ----------
        key : str
            復号時に必要となるパスワードです。
        content : str
            暗号化する文章です。

        Examples
        --------
        `rf!reprypt encrypt tasuren 私の極秘情報！`

        Aliases
        -------
        en

        Notes
        -----
        この機能にはAPIがあります。  
        URI:`/api/reprypt` POST/OPTIONS
        ```json
        {
            "mode": "encrypt",
            "content": "暗号化する文字列",
            "password": "パスワード"
        }
        ```

        !lang en
        --------

        Encrypts the specified text.

        Parameters
        ----------
        key : str
            The password required for decryption.
        content : str
            The text to be encrypted.

        Examples
        --------
        `rf!reprypt encrypt tasuren My top secret!`

        Aliases
        -------
        en

        Notes
        -----
        This has an API.  
        URI:`/api/reprypt` POST/OPTIONS
        ```json
        {
            "mode": "encrypt",
            "content": "String to encrypt",
            "password": "password"
        }
        ```"""
        result = reprypt.encrypt(content, key)
        await ctx.reply(
            f"```\n{result}\n```", replace_language=False,
            allowed_mentions=discord.AllowedMentions.none()
        )

    @reprypt_.command(aliases=["de"])
    async def decrypt(self, ctx, key, *, content):
        """!lang ja
        --------
        Repryptで暗号化された文章を復号化します。

        Parameters
        ----------
        key : str
            暗号化する時に使ったパスワードです。
        content : str
            復号したい暗号化された文章です。

        Aliases
        -------
        de

        Examples
        --------
        `rf!reprypt encrypt tasuren ByGqa44We55B1u56e5oYO65FC77x`

        Notes
        -----
        この機能にはAPIがあります。  
        URI:`/api/reprypt` POST/OPTIONS
        ```json
        {
            "mode": "decrypt",
            "content": "復号化する暗号",
            "password": "パスワード"
        }
        ```

        !lang en
        --------
        Decrypts the text encrypted by Reprypt.

        Parameters
        ----------
        key : str
            The password used for encryption.
        content : str
            The encrypted text to be decrypted.

        Aliases
        -------
        de

        Examples
        --------
        `rf!reprypt encrypt tasuren ByGqa44We55B1u56e5oYO65FC77x`

        Notes
        -----
        There is an API for this.  
        URI:`/api/reprypt` POST/OPTIONS
        ```json
        {
            "mode": "decrypt",
            "content": "Cipher to decrypt",
            "password": "password"
        }
        ```"""
        result = reprypt.decrypt(content, key)
        await ctx.reply(
            f"```\n{result}\n```", replace_language=False,
            allowed_mentions=discord.AllowedMentions.none()
        )

    async def reprypt_api(self, request):
        headers = {"Access-Control-Allow-Origin": "*"}
        now = time()
        if int(now) - int(self.rate.get(request.ip, 0)) < 3:
            return sanic.response.json(
                {"result": None,
                    "message": "Too many request.",
                    "status": 429},
                status=429,
                headers=headers
            )
        data = request.json
        content = data.get("content")
        password = data.get("password")
        mode = data.get("mode")
        if not (content and password and mode):
            return sanic.response.json(
                {"result": None,
                    "message": "I don't receive the content I need.",
                    "status": 400},
                status=400,
                headers=headers
            )
        if mode not in ["de", "en", "decrypt", "encrypt"]:
            return sanic.response.json(
                {"result": None,
                 "message": "The mode cannot be use.",
                 "status": 400},
                status=400,
                headers=headers
            )
        self.rate[request.ip] = now
        try:
            if mode in ["en", "encrypt"]:
                result = reprypt.encrypt(content, password)
            else:
                result = reprypt.decrypt(content, password)
        except Exception as e:
            return sanic.response.json(
                {"result": None,
                    "message": ("I got some error!\nMake sure your password "
                                + "is right if the mode is de.\n"
                                + "error: " + " ".join(e.args)),
                    "status": 500},
                status=500,
                headers=headers
            )
        data = {
            "result": result,
            "message": "success",
            "status": 200
        }
        return sanic.response.json(data, headers=headers)


async def setup(bot):
    await bot.add_cog(Reprypt(bot))
