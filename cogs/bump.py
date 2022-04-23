# Free RT - Bump

from typing import Any, Literal

from discord.ext import commands, tasks
import discord

from util.mysql_manager import DatabaseManager

from asyncio import sleep
from ujson import loads
from time import time


class DataManager(DatabaseManager):
    def __init__(self, db):
        self.db = db

    async def init_table(self, cursor) -> None:
        await cursor.create_table(
            "bump", {
                "GuildID": "BIGINT", "Mode": "TEXT",
                "Data": "TEXT"
            }
        )
        await cursor.create_table(
            "bumpRanking", {
                "UserID": "BIGINT", "Mode": "TEXT", "Count": "INTEGER"
            }
        )

    async def save(self, cursor, guild_id: int, mode: str, data: dict) -> None:
        target = {"GuildID": guild_id, "Mode": mode}
        if await cursor.exists("bump", target):
            await cursor.delete("bump", target)
        target["data"] = data
        await cursor.insert_data("bump", target)

    async def load(self, cursor, guild_id: int, mode: str) -> list:
        target = {"GuildID": guild_id, "Mode": mode}
        if await cursor.exists("bump", target):
            return await cursor.get_data("bump", target)
        else:
            return [guild_id, mode, {"onoff": True}]

    async def save_ranking(self, cursor, user_id: int, mode: str, count: int) -> None:
        target = {"UserID": user_id, "Mode": mode}
        change = {"Count": count}
        if await cursor.exists("bumpRanking", target):
            await cursor.update_data("bumpRanking", change, target)
        else:
            target.update(change)
            await cursor.insert_data("bumpRanking", target)

    async def load_ranking(self, cursor, user_id: int, mode: str) -> int:
        target = {"UserID": user_id, "Mode": mode}
        if await cursor.exists("bumpRanking", target):
            if (row := await cursor.get_data("bumpRanking", target)):
                return row[-1]
            else:
                return 0
        else:
            return 0

    async def execute(self, cursor, cmd: str, args: tuple, fetch: bool = True) -> Any:
        await cursor.cursor.execute(cmd, args)
        if fetch:
            return await cursor.cursor.fetchall()


def get_extras(mode: str) -> dict:
    return {
        "headding": {
            "ja": f"{mode}の通知のON/OFFをします。",
            "en": f"Change {mode} notification on/off."
        },
        "parent": "ServerTool"
    }


class Bump(commands.Cog, DataManager):
    
    IDS = {
        302050872383242240: {
            "mode": "bump",
            "description": ["表示順をアップしたよ", "Bump done", "Bumpeado", "Bump effectue"],
            "time": 7200
        },
        761562078095867916: {
            "mode": "up",
            "description": ["dissoku"],
            "time": 3600
        },
        716496407212589087: {
            "mode": "raise",
            "description": ["Raised"],
            "time": 14106
        }
    }
    BUMP_COLOR = 0x00a3af
    UP_COLOR = 0x95859c
    EMOJIS = {
        "1": "<:No1:795849530448805919>",
        "2": "<:No2:795849531774205994>",
        "3": "<:No3:795849531840397323>"
    }

    def __init__(self, bot):
        self.bot = bot
        self.bot.loop.create_task(self.on_ready())

    async def on_ready(self):
        super(commands.Cog, self).__init__(
            self.bot.mysql
        )
        await self.init_table()
        self.notification.start()

    async def write(
        self, mode: Literal["bump", "up"], guild_id: int,
        onoff: bool, role: discord.Role = None
    ) -> None:
        await self.save(
            guild_id, mode, {"role": getattr(role, "id", 0), "onoff": onoff}
        )

    @commands.command(extras=get_extras("bump"))
    @commands.has_guild_permissions(administrator=True)
    @commands.cooldown(1, 10, commands.BucketType.user)
    async def bump(self, ctx, onoff: bool, *, role: discord.Role = None):
        """!lang ja
        --------
        Bump通知のOnOffコマンドです。

        Parameters
        ----------
        onoff : bool
            onにするかoffにするかです。
        role : 役職名またはメンション, optional
            通知する際にメンションする役職です。  
            選択しなくても実行できます。

        Examples
        --------
        `rf!bump on Bump係`

        Notes
        -----
        この機能はデフォルトでonです。

        !lang en
        --------
        Bump notification on/off command.

        Parameters
        ----------
        onoff : bool
            This is on or off.
        role : Role name or mention, optional
            Mention of role when do notification.  
            This is a option.

        Examples
        --------
        `rf!bump on BumpMan`

        Notes
        -----
        Bump notification is enable by default."""
        await self.write("bump", ctx.guild.id, onoff, role)
        await ctx.reply("Ok", replace_language=False)

    @commands.command(extras=get_extras("up"))
    @commands.has_guild_permissions(administrator=True)
    async def up(self, ctx, onoff: bool, *, role: discord.Role = None):
        await self.write("up", ctx.guild.id, onoff, role)
        await ctx.reply("Ok", replace_language=False)

    @commands.command(extras=get_extras("raise"))
    @commands.has_guild_permissions(administrator=True)
    async def raisenof(self, ctx, onoff: bool, *, role: discord.Role = None):
        await self.write("raise", ctx.guild.id, onoff, role)
        await ctx.reply("Ok", replace_language=False)

    up._callback.__doc__ = bump.callback.__doc__.replace("bump", "up").replace("Bump", "Up")
    raisenof._callback.__doc__ = bump.callback.__doc__.replace("bump", "raise").replace("Bump", "Raise")

    async def make_ranking(self, user_id: int, mode: str) -> discord.Embed:
        rows = await self.execute(
            """SELECT * FROM bumpRanking
                WHERE Mode = %s
                ORDER BY Count DESC
                LIMIT 5""", (mode,)
        )
        now = await self.load_ranking(user_id, mode)

        # ランキングのEmbedを作る。
        embed = discord.Embed(
            title=f"{mode} ランキング / Ranking",
            description={
                "ja": f"あなたの{mode}回数は{now}です。",
                "en": f"Your {mode} count is {now}."
            },
            color=self.BUMP_COLOR if mode == "bump" else self.UP_COLOR
        )
        i = 0
        embed.add_field(
            name="?\n",
            value="\n".join((
                f"{self.EMOJIS.get(str_i := str(i := i + 1), str_i)} " # noqa
                f"{(name := getattr(self.bot.get_user(row[0]), 'name', 'ユーザー不明'))}"
                f"：{row[-1]}") for row in rows
            )
        )

        del i, str_i
        return embed

    def cog_unload(self):
        self.notification.cancel()

    async def get_all(self, mode: str) -> tuple:
        return await self.execute(
            "SELECT * FROM bump WHERE Mode = %s",
            (mode,)
        )

    REPLIES = {"bump": "/bump", "up": "/dissoku up", "raise": "rf!raise"}

    @tasks.loop(seconds=10)
    async def notification(self):
        now = time()
        for key in self.IDS:
            mode = self.IDS[key]["mode"]
            for row in await self.get_all(mode):
                row = list(row)
                try:
                    row[-1] = loads(row[-1])
                except Exception as e:
                    if self.bot.test:
                        print("Error on bump:", e)
                else:
                    if "notification" in row[-1]:
                        if (row[-1]["notification"] <= now
                            and row[-1]["notification"] != 0):
                            # もし通知時刻になっているなら通知をする。
                            channel = self.bot.get_channel(
                                int(row[-1]["channel"])
                            )
                            if channel:
                                role = channel.guild.get_role(row[-1].get("role", 0))
                                kwargs = {}
                                if role:
                                    kwargs["content"] = role.mention
                                kwargs["embed"] = discord.Embed(
                                    title=f"Time to {mode}!",
                                    description=f"{mode}の時間です。\n" \
                                        f"`{self.REPLIES[mode]}`" \
                                        "でこのサーバーの表示順位を上げよう！",
                                    color=self.bot.colors["normal"]
                                )
                                try:
                                    await channel.send(**kwargs)
                                except Exception as e:
                                    if self.bot.test:
                                        print("Error on bump2:", e)

                                # 通知時刻をまた通知しないようにゼロにする。
                                row[-1]["notification"] = 0
                                await self.save(channel.guild.id, mode, row[-1])

    async def delay_on_message(self, seconds: int, message: discord.Message) -> None:
        # 遅れて再取得してもう一回on_messageを実行する。
        await sleep(seconds)
        try:
            message = await message.channel.fetch_message(message.id)
        except discord.NotFound:
            ...
        else:
            await self.on_message(message, True)

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message, retry: bool = False):
        if not self.bot.is_ready():
            return

        data = self.IDS.get(message.author.id)
        if not retry and data and data["mode"] != "bump":
            # もしDissoku/rocationsなら数秒後に再取得してもう一度この関数on_messageを呼び出す。
            self.bot.loop.create_task(self.delay_on_message(5, message))
            return
        if not message.guild or not data or (data["mode"] != "raise" and not message.embeds):
            return

        desc = message.content if data["mode"] == "raise" else message.embeds[0].description
        check = desc and any(
            word in desc for word in data["description"]
        ) if data["mode"] != "up" else (
            message.embeds[0].fields
            and "をアップしたよ" in message.embeds[0].fields[0].name
        )

        if check:
            row = await self.load(message.guild.id, data["mode"])
            if row and row[-1]["onoff"]:
                # 既に書き込まれてるデータに次通知する時間とチャンネルを書き込む。
                new = row[-1]
                new["notification"] = time() + data["time"]
                new["channel"] = message.channel.id
                await self.save(message.guild.id, data["mode"], new)

                # 通知の設定をしたとメッセージを送る。
                try:
                    await message.channel.send(
                        embed=discord.Embed(
                            title="通知設定",
                            description=f"{data['mode']}の通知を設定しました。\n" \
                                + f"<t:{int(new['notification'])}:R>に通知します。",
                            color=self.bot.colors["normal"]
                        )
                    )
                except discord.Forbidden:
                    ...


def setup(bot):
    bot.add_cog(Bump(bot))
