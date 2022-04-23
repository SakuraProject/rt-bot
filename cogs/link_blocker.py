# Free RT - Link Blocker

from typing import TYPE_CHECKING, List

from discord.ext import commands
import discord

from util import RT

if TYPE_CHECKING:
    from aiomysql import Pool, Cursor


class DataManager:

    TABLES = ("LinkBlocker", "LinkBlockerIgnores")

    def __init__(self, cog: "LinkBlocker"):
        self.cog = cog
        self.pool: "Pool" = self.cog.bot.mysql.pool
        self.cog.bot.loop.create_task(self._prepare_table())

    async def _prepare_table(self) -> None:
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"""CREATE TABLE IF NOT EXISTS {self.TABLES[0]} (
                        GuildID BIGINT
                    );"""
                )
                await cursor.execute(
                    f"CREATE TABLE IF NOT EXISTS {self.TABLES[1]} (ChannelID BIGINT);"
                )
                self.cog.guilds = await self.reads(cursor)
                self.cog.ignores = await self.read_ignores(cursor)

    async def toggle(self, guild_id: int) -> bool:
        """サーバーのリンクブロックのOnOffを切り替えます。"""
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"""SELECT * FROM {self.TABLES[0]}
                    WHERE GuildID = %s;""",
                    (guild_id,)
                )
                if await cursor.fetchone():
                    await cursor.execute(
                        f"DELETE FROM {self.TABLES[0]} WHERE GuildID = %s;",
                        (guild_id,)
                    )
                    return False
                else:
                    await cursor.execute(
                        f"INSERT INTO {self.TABLES[0]} VALUES (%s);",
                        (guild_id,)
                    )
                    return True

    async def reads(self, cursor: "Cursor") -> List[int]:
        """設定されているサーバーのリストを取得します。"""
        await cursor.execute(f"SELECT * FROM {self.TABLES[0]};")
        return [row[0] for row in await cursor.fetchall() if row]

    async def add_ignore(self, channel_id: int) -> None:
        """無視リストにチャンネルIDを追加します。"""
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"INSERT INTO {self.TABLES[1]} VALUES (%s);",
                    (channel_id,)
                )

    async def remove_ignore(self, channel_id: int) -> None:
        """無視リストからチャンネルを削除します。"""
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"DELETE FROM {self.TABLES[1]} WHERE ChannelID = %s;",
                    (channel_id,)
                )

    async def read_ignores(self, cursor: "Cursor") -> List[int]:
        """無視リストを取得します。"""
        await cursor.execute(f"SELECT * FROM {self.TABLES[1]};")
        return [row[0] for row in await cursor.fetchall() if row]


class LinkBlocker(commands.Cog, DataManager):
    def __init__(self, bot: RT):
        self.bot = bot
        self.guilds: List[int] = []
        self.ignores: List[int] = []
        super(commands.Cog, self).__init__(self)

    @commands.group(
        aliases=["URLブロック", "lb"], extras={
            "headding": {
                "ja": "URLをブロックする機能です。",
                "en": "This feature blocks URLs."
            }, "parent": "ServerSafety"
        }
    )
    @commands.cooldown(1, 10, commands.BucketType.user)
    @commands.has_guild_permissions(manage_messages=True)
    async def linkblock(self, ctx):
        """!lang ja
        --------
        URLが送信された時にメッセージを削除する機能です。  
        `rf!linkblock`を実行することでオン/オフを切り替えることができます。

        Aliases
        -------
        lb, URLブロック

        !lang en
        --------
        This feature will delete a message that included a URL.  
        You can toggle on or off by running this command (`rf!linkblock`).

        Aliases
        -------
        lb"""
        if not ctx.invoked_subcommand:
            if (onoff := await self.toggle(ctx.guild.id)):
                self.guilds.append(ctx.guild.id)
            else:
                self.guilds.remove(ctx.guild.id)
            await ctx.reply(
                f"リンクブロックを{'有効' if onoff else '無効'}にしました。"
            )

    HELP = ("ServerSafety", "linkblock")
    # 最大の設定できる例外チャンネルの数です。
    MAX_CHANNELS = 25

    @linkblock.command(aliases=["a", "追加"])
    async def add(self, ctx):
        """!lang ja
        --------
        URLを送ってもメッセージが削除されない例外のチャンネルを追加します。  
        実行したチャンネルが追加されます。25個まで登録できます。

        Aliases
        -------
        a, 追加

        !lang en
        --------
        Add an exception channel where sending a URL will not delete the message.  
        The target will set the channel that runs this command.

        Aliases
        -------
        a"""
        if ctx.channel.id not in self.ignores:
            self.ignores.append(ctx.channel.id)
            if len(self.ignores) < self.MAX_CHANNELS:
                await self.add_ignore(ctx.channel.id)
                await ctx.reply("Ok")
            else:
                await ctx.reply(
                    {"ja": "これ以上例外設定を登録することはできません。",
                     "en": "No more exception settings can be added."}
                )
        else:
            await ctx.reply(
                {"ja": "既に追加されています。",
                 "en": "The channel is already added."}
            )

    @linkblock.command(aliases=["rm", "delete", "del", "削除"])
    async def remove(self, ctx, channel_id: int = None):
        """!lang ja
        --------
        URLブロッカーの例外リストからチャンネルを削除します。   
        実行したチャンネルまたは引数に渡されたチャンネルIDが削除されます。

        Parameters
        ----------
        channel_id : int, optional
            削除するチャンネルのIDです。  
            指定しなかった場合は実行したチャンネルを例外リストから削除します。

        Aliases
        -------
        rm, delete, del, 削除

        !lang en
        --------
        Remove an exception channel where sending a URL will not delete the message.  

        Parameters
        ----------
        channel_id : int, optional
            Remove target channel's id.  
            If you don't select this argument, the target will set the channel that runs this command.

        Aliases
        -------
        rm, delete, del"""
        channel_id = channel_id or ctx.channel.id
        if ctx.channel.id in self.ignores:
            self.ignores.remove(channel_id)
            await self.remove_ignore(channel_id)
            await ctx.reply("Ok")
        else:
            await ctx.reply(
                {"ja": "このチャンネルは追加されていません。",
                 "en": "The channel is not added."}
            )

    @linkblock.command(
        "list", aliases=["一覧", "l"], 
        extras={
            "headding": {
                "ja": "URLブロッカーの例外リストです。",
                "en": "URL Blocker's ignore list"
            }
        }
    )
    async def list_(self, ctx):
        """!lang ja
        --------
        URLブロッカーの例外に指定されているチャンネルのリストを表示します。

        Aliases
        -------
        l, 一覧

        !lang en
        --------
        Displays exception settings list.

        Aliases
        -------
        l"""
        await ctx.reply(
            embed=discord.Embed(
                title={
                    "ja": f"{self.__cog_name__}に設定されている例外チャンネル",
                    "en": f"{self.__cog_name__}'s exception settings"
                }, description=", ".join(
                    f"<#{channel.id}>" for channel in self.ignores
                ), color=self.bot.colors["normal"]
            )
        )

    SCHEMES = ("https://", "http://")

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if (message.guild and message.guild.id in self.guilds
                and any(scheme in message.content for scheme in self.SCHEMES)
                and message.channel.id not in self.ignores):
            await message.delete()
            content = {
                "ja": "このチャンネルではURLを送信することができません。",
                "en": "You can't send the URL on the channel."
            }
            try:
                await message.author.send(content)
            except:
                await message.channel.send(content)


def setup(bot):
    bot.add_cog(LinkBlocker(bot))
