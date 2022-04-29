from discord.ext import commands, tasks
import discord
from util import RT
from datetime import datetime
from asyncio import Event
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aiomysql import Pool

TABLES = ("schedule", "schedule_test")


class DataManager:
    def __init__(self, cog: "schedule"):
        self.cog = cog
        self.pool: "Pool" = cog.bot.mysql.pool
        self.cog.bot.loop.create_task(self._prepare_table())

    async def _prepare_table(self):
        # テーブルの準備をする。このクラスのインスタンス化時に自動で実行される。
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"""CREATE TABLE IF NOT EXISTS {TABLES[0]} (
                        UserID BIGINT NOT NULL, body TEXT, stime TEXT, etime TEXT, day TEXT, dmnotice VARCHAR(3)
                    );"""
                )
                # キャッシュを用意しておく。
                await cursor.execute(f"SELECT * FROM {TABLES[0]};")
                for row in await cursor.fetchall():
                    if row and row[1]: 
                        try: 
                            self.cog.cache[row[0]][row[1]] = {'UserID': row[0], 'body': row[1], 'stime': row[2], 'etime': row[3], 'day': row[4], 'dmnotice': row[5]}
                        except KeyError:
                            self.cog.cache[row[0]] = dict()
                            self.cog.cache[row[0]][row[1]] = {'UserID': row[0], 'body': row[1], 'stime': row[2], 'etime': row[3], 'day': row[4], 'dmnotice': row[5]}
        self.cog.ready.set()


class schedule(commands.Cog, DataManager): 

    def __init__(self, bot: RT): 
        self.bot, self.before = bot, ""
        self.cache = dict()
        super(commands.Cog, self).__init__(self)
        self.ready = Event()
        self.pool: "Pool" = self.bot.mysql.pool
        self.process_notice.start()

    @commands.group(
        aliases=["予定", "sch"], extras={
            "headding": {
                "ja": "スケジュール機能",
                "en": "Setting schedule"
            }, "parent": "Individual"
        }
    )
    async def schedule(self, ctx: commands.Context): 
        """!lang ja
        --------
        discord上で予定を管理できるようにする機能です

        !lang en
        --------
        this command is add schedule manage function to discord"""
        if not ctx.invoked_subcommand: 
            await ctx.reply(
                {"ja": "使用方法が違います。",
                 "en": "It is wrong way to use this command."}
            )

    @schedule.command(
        "set", aliases=["s", "設定"],
        extras={
            "headding": {
                "ja": "予定を設定します。",
                "en": "Set schedule"
            }
        }
    )
    async def set_(self, ctx: commands.Context, start, end, day, notice, *, title): 
        """!lang ja
        --------
        予定を設定します。

        Parameters
        ----------
        start : str
            予定開始時間です
        end : str
            予定終了時間です
        day : str
            日付です
        notice : str
            予定開始時間にDM通知するかです
        title : str
            予定一覧に表示されるタイトルです
        Examples
        --------
        `rf!afk set 12:00 19:00 2022/05/01 off 友達とお出かけ`
        `rf!afk set 12:00 14:00 2022/05/01 on お食事`

        Aliases
        -------
        s, 設定

        !lang en
        --------
        Sets the schedule.

        Parameters
        ----------
        start : str
            start time
        end : str
            time of end
        day : str
            day
        notice : str
            dm notice setting
        title : str
            schedule title

        Examples
        --------
        `rf!afk set 12:00 19:00 2022/05/01 off travel`
        `rf!afk set 12:00 14:00 2022/05/01 on lunch`

        Aliases
        -------
        s"""
        await ctx.trigger_typing()
        await self.set_schedule(ctx.author.id, start, end, day, notice, title)
        await ctx.reply("Ok")

    @schedule.command(
        aliases=["del", "削除"],
        extras={
            "headding": {
                "ja": "AFKプラスの設定を削除します。", "en": "Delete AFK Plus"
            }
        }
    )
    async def delete(self, ctx: commands.Context, *, title):
        """!lang ja
        --------
        設定した予定を削除します

        Parameters
        ----------
        title : str
            設定の際に入力した引数の`title`です。

        Aliases
        -------
        del, 削除

        !lang en
        --------
        Cancels the schedule setting.

        Parameters
        ----------
        title : str
            This is the `title` argument you entered when setting schedule.

        Aliases
        -------
        del"""
        try:
            await self.delete_schedule(ctx.author.id, title)
        except AssertionError:
            await ctx.reply(
                {"ja": "その予定が見つかりませんでした。",
                 "en": "The schedule is not found."}
            )
        except KeyError:
            await ctx.reply(
                {"ja": "その予定が見つかりませんでした。",
                 "en": "The schedule is not found."}
            )
        else:
            await ctx.reply("Ok")

    @tasks.loop(seconds=10)
    async def process_notice(self):
        try:
            await self.ready.wait()
            now = datetime.now()
            now = now.strftime("%Y/%m/%d%H:%M")

            if self.before != now:
                self.before = now

                for user_id, datas in list(self.cache.items()):
                    for title, data in datas.items():
                        if data['day'] + data['stime'] == now:
                            if (user := self.bot.get_user(user_id)):
                                if data['dmnotice'] == "on":
                                    await user.send("予定のお時間です\n予定:" + title)
                            else:
                                # もしユーザーが見つからなかったのならそのデータを削除する。
                                await self.delete(user_id)
                        if data['day'] + data['etime'] == now:
                            try:
                                await self.delete_schedule(user_id, title)
                            except AssertionError:
                                len('test')
        except Exception:
            datetime.now()

    async def delete_schedule(self, userid, data) -> None:
        for title, d in self.cache[userid].items():
            if title == data:
                del self.cache[userid][title]
                async with self.pool.acquire() as conn:
                    async with conn.cursor() as cursor:
                        await cursor.execute(
                            f"""DELETE FROM {TABLES[0]}
                                WHERE UserID = %s AND body = %s;""",
                            (userid, title)
                        )
                break
        else:
            assert False, "その予定は設定されていません。"

    @schedule.command(
        "list", aliases=["l", "一覧"],
        extras={
            "headding": {
                "ja": "予定リストを表示します。",
                "en": "Show you the schedule list."
            }
        }
    )
    async def list_(self, ctx: commands.Context):
        """!lang ja
        --------
        設定している予定の一覧を表示します。

        !lang en
        --------
        Displays a list of configured schedule."""
        try:
            data = self.cache[ctx.author.id]
            embed = discord.Embed(
                title=self.__cog_name__, color=self.bot.colors["normal"]
            )
            days = dict()
            for body, d in data.items():
                try:
                    days[d['day']].append(d)
                except KeyError:
                    days[d['day']] = list()
                    days[d['day']].append(d)
            sdays = sorted(days.items(), key=lambda x: x[0])
            for dal in sdays:
                val = ""
                for dt in dal[1]:
                    val = val + dt['stime'] + "~" + dt['etime'] + '\n' + dt['body'] + "\n"
                embed.add_field(
                    name=dal[0],
                    value=val
                )
            await ctx.reply(embed=embed)
        except KeyError:
            await ctx.reply("予定はありません")

    async def set_schedule(self, userid, start, end, day, notice, title: str = None) -> None:
        if title:
            try:
                self.cog.cache[userid][title] = dict()
            except KeyError:
                self.cog.cache[userid] = dict()
                self.cog.cache[userid][title] = dict()
            self.cog.cache[userid][title]['stime'] = start
            self.cog.cache[userid][title]['etime'] = end
            self.cog.cache[userid][title]['day'] = day
            self.cog.cache[userid][title]['dmnotice'] = notice
            self.cog.cache[userid][title]['body'] = title
        elif userid in self.cog.cache:
            del self.cog.cache[userid]
        if title is None:
            title = ""
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"INSERT INTO {TABLES[0]} VALUES (%s, %s, %s, %s, %s, %s);",
                    (userid, title, start, end, day, notice)
                )

    def cog_unload(self):
        self.process_notice.cancel()


def setup(bot):
    bot.add_cog(schedule(bot))
