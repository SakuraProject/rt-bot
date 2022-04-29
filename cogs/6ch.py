# Free RT Ext - 6ch

from aiofiles import open as async_open
from ujson import load, dumps
from random import randint
from datetime import date
import reprypt

from discord.ext import commands


def rname() -> str:
    chars = ""
    for i in range(10):
        chars += randint(0, 9)
    return chars


class SixChannel(commands.Cog):
    def __init__(self, bot):
        self.bot, self.rt = bot, bot.data
        self.data = {"thread": {}, "nickname": {}, "id": {}}
        self.path = "data/6ch.json"
        try:
            with open(self.path, "r") as f:
                self.data = load(f)
        except Exception:
            with open(self.path, "w") as f:
                f.write(dumps(self.data))

    async def save(self, path, data, indent):
        async with async_open(path, "w") as f:
            await f.write(dumps(data, indent=indent))

    @commands.group(
        name="6ch", aliases=["ch"], extras={
            "headding": {
                "ja": "掲示板",
                "en": "6ch, BBS"
            }, "parent": "Entertainment"
        }
    )
    async def sixch(self, ctx):
        """!lang ja
        ---------
        2ちゃんねるのような掲示板を作れる機能です。

        !lang en
        --------
        Make BBS like 4chan."""
        if not ctx.invoked_subcommand:
            if self.data["thread"]:
                n = "".join(
                    (f"{key.replace('@', '＠')}, 作者："
                     + getattr(self.bot.get_user(data["author"]), "name", "???")
                     .replace("@", "＠"))
                    for key, data in list(self.data["thread"].items())
                )
                await ctx.reply(n)
            else:
                await ctx.reply("まだありません。")

    @sixch.command()
    async def new(self, ctx, *, name):
        """!lang ja
        -------
        新しくスレッドを作ります。

        Parameters
        ----------
        name : str
            作成するスレッドの名前です。

        !lang en
        --------
        Create a new thread.

        Parameters
        ----------
        name : str
            The name of the thread to be created."""
        if name in self.data["thread"]:
            await ctx.reply("その名前のスレッドは既にあります。")
        else:
            self.data["thread"][name] = {
                "log": [],
                "author": ctx.author.id,
                "channels": [],
                "count": 0
            }
            await self.save(self.path, self.data, 4)
            await ctx.reply("設定しました。")

    @sixch.command(aliases=["cng"])
    @commands.has_permissions(manage_channels=True)
    async def connect(self, ctx, *, name):
        """!lang ja
        --------
        6chの既にあるスレッドに接続します。

        Parameters
        ----------
        name : str
            接続するスレッドの名前です。"""
        if name in self.data["thread"]:
            self.data["thread"][name]["channels"].append(ctx.channel.id)
            await ctx.reply("設定しました。")
        else:
            await ctx.reply("その名前のスレッドが見つかりませんでした。")

    @sixch.command(name="del", aliases=["delete", "remove", "rm"])
    async def _del(self, ctx):
        await ctx.reply("`rf!info`からサポートサーバーにて管理者に問い合わせてください。")

    @sixch.command(aliases=["nick"])
    async def nickname(self, ctx, *, name):
        """!lang ja
        --------
        スレッドで使うニックネームを設定します。

        Parameters
        ----------
        name : str
            ニックネームです。"""
        self.data["nickname"][str(ctx.author.id)] = name
        await self.save(self.path, self.data, 4)
        await ctx.reply("設定しました。")

    @commands.Cog.listener()
    async def on_message(self, message):
        if message.author.bot or message.content.startswith("rf!"):
            return

        for name in self.data["thread"]:
            chs = self.data["thread"][name]["channels"]
            if message.channel.id in chs:
                data = self.data["thread"][name]
                u = self.data["nickname"].get(
                    str(message.author.id), message.author.name)
                # もし通報時用のユーザーIDがなかったら作る。
                if str(message.author.id) not in self.data:
                    # Repryptで送信者のIDを暗号化してできたIDを使う。
                    uid = reprypt.encrypt(
                        str(message.author.id), "6chの語源はRT")
                    self.data["id"][str(message.author.id)] = uid
                # メッセージ作成。
                uid = self.data["id"][str(message.author.id)]
                c = f"{data['count']}：**{u}**：{date.today()}：{uid}"
                c += "\n" + message.clean_content
                # カウントアップする。
                self.data["thread"][name]["count"] += 1
                # 送信する。
                await message.delete()
                await message.channel.send(c)
                self.data["thread"][name]["log"].append(c)
                await self.save(self.path, self.data, 4)
                break


def setup(bot):
    bot.add_cog(SixChannel(bot))
