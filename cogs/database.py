# Free RT - Database Manager

from discord.ext import commands
import discord

from aiofiles import open as aioopen
from aiofiles.os import remove

from util import RT


class DatabaseManager(commands.Cog):
    def __init__(self, bot: RT):
        self.bot = bot

    @commands.command(
        description="渡された命令文でデータベースを操作します。",
        extras={"parent": "Admin"}, aliases=["db", "mysql", "execute", "実行"]
    )
    @commands.is_owner()
    async def sql(
        self, ctx, show: bool = discord.SlashOption("show", "実行結果を表示するかどうかです。"),
        *, cmd: str = discord.SlashOption("sql", "SQLの命令文です。")
    ):
        """!lang ja
        --------
        データベースで任意のコマンドを実行します。  
        当たり前ですが管理者しか実行できません。

        Notes
        -----
        Free RTのデータベースへの接続に使用しているラッパーは`aiomysql`です。  
        その`aiomysql`のオプションで自動コミットするようにしています。

        Parameters
        ----------
        show : bool
            実行結果を表示するかどうかです。
        cmd : str
            実行するコードです。

        !lang en
        --------
        No description."""
        result = None
        async with self.bot.mysql.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(cmd)
                if show:
                    result = "\n".join(
                        map(lambda x: "\t".join(map(str, x)),
                            await cursor.fetchall())
                    )
            if result is None:
                await ctx.reply("Ok")
            else:
                if len(result) > 2000:
                    async with aioopen(
                        name := f"sql_{ctx.author.id}_result.txt", "w"
                    ) as f:
                        await f.write(result)
                    await ctx.reply("Ok", file=discord.File(name))
                    await remove(name)
                else:
                    await ctx.reply(f"Ok\n```\n{result}\n```")


def setup(bot):
    bot.add_cog(DatabaseManager(bot))
