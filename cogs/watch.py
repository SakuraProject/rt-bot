# Free RT - Watch

from __future__ import annotations

from typing import Union

from dataclasses import dataclass
from time import time

from discord.ext import commands, tasks
import discord

from util import RT


@dataclass
class Timer:
    "チアマークラスです。"

    channel: Union[discord.TextChannel, discord.Thread]
    author: Union[discord.User, discord.Member]
    content: str
    rt: bool
    deadline: float

    async def process(self) -> bool:
        "タイマーが終了かどうかをチェックして終了した場合はメッセージを送信します。終了したかどうかの真偽値を返します。"
        if time() >= self.deadline:
            if self.rt:
                await self.channel.send(f"{self.author.mention}, タイマーが終了しました！")
            elif isinstance(self.channel, discord.Thread):
                await self.channel.send(
                    discord.Embed(
                        description=self.content
                    ).set_author(
                        name=self.author, icon_url=getattr(self.author.avatar, "url", "")
                    ).set_footer(
                        text="RTのタイマー"
                    )
                )
            else:
                await self.channel.webhook_send(
                    content=self.content.replace("@", "＠"),
                    username=f"{self.author} - RTのタイマー", avatar_url=getattr(
                        self.author.avatar, "url", ""
                    )
                )
            return True
        return False


class Watch(commands.Cog):
    def __init__(self, bot: RT):
        self.bot = bot
        self.sw: dict[int, float] = {}
        self.timers: dict[int, Timer] = {}
        self.timer_processer.start()

    @commands.group(
        aliases=["w", "時計"], extras={
            "parent": "Individual", "headding": {
                "ja": "時計, ストップウォッチ, タイマー",
                "en": "watch, stopwatch, timer"
            }
        }
    )
    async def watch(self, ctx: commands.Context):
        """!lang ja
        --------
        時計です。
        `rf!watch`で現在の時刻と日付を表示します。

        !lang en
        --------
        This is a watch.
        `rf!watch` to display date and time."""
        if not ctx.invoked_subcommand:
            await ctx.reply(f"現在の時刻は<t:{int(time())}:F>です。")

    @watch.group(aliases=["sw", "ストップウォッチ"], description="ストップウォッチ")
    async def stopwatch(self, ctx: commands.Context):
        """!lang ja
        --------
        ストップウォッチです。

        Aliases
        -------
        sw, ストップウォッチ

        !lang en
        --------
        Stop Watch

        Aliases
        -------
        sw"""
        if not ctx.invoked_subcommand:
            await ctx.reply("使用方法が違います。")

    @stopwatch.command(aliases=["a", "開始"])
    async def start(self, ctx: commands.Context):
        """!lang ja
        --------
        ストップウォッチを開始します。

        Notes
        -----
        ストップウォッチは一つまでしか同時に動かせません。
        ですので既にストップウォッチが動いてる状態で開始した場合はそのストップウォッチは無効となります。

        Warnings
        --------
        これはRTが再起動されると無効になります。
        もし数日以上動かすストップウォッチのつもりの場合はこれを使わない方が良いです。

        Aliases
        -------
        a, 開始

        !lang en
        --------
        Starts the stopwatch.

        Notes
        -----
        Only one stopwatch can be running at a time.
        Therefore, if you start a stopwatch when one is already running, the stopwatch will be invalid.

        Warnings
        --------
        This will be disabled when RT is restarted.
        If you plan to run the stopwatch for more than a few days, it is best not to use this.

        Aliases
        -------
        a"""
        self.sw[ctx.author.id] = time()
        await ctx.reply("ストップウォッチをスタートしました。")

    def time_str(self, t: Union[int, float]) -> str:
        "秒数を`01:39`のような`分：秒数`の形にする。"
        return ":".join(
            map(lambda o: (
                str(int(o[1])).zfill(2)
                if o[0] or o[1] <= 60
                else self.time_str(o[1])
            ), ((0, t // 60), (1, t % 60)))
        )

    @stopwatch.command(aliases=["o", "停止"])
    async def stop(self, ctx: commands.Context):
        """!lang ja
        --------
        ストップウォッチを停止します。

        Aliases
        -------
        o, 停止

        !lang en
        --------
        Stop stopwatch.

        Aliases
        -------
        o"""
        if ctx.author.id in self.sw:
            await ctx.reply(
                "ストップウォッチを停止しました。\n"
                f"経過時間：`{self.time_str(time() - self.sw[ctx.author.id])}`"
            )
            del self.sw[ctx.author.id]
        else:
            await ctx.reply("ストップウォッチが開始していません。")

    @watch.command(aliases=["t", "タイマー"], description="タイマー")
    @commands.cooldown(1, 15, commands.BucketType.user)
    async def timer(
        self, ctx: commands.Context, minutes: float, *, content: str = None
    ):
        """!lang ja
        --------
        タイマーを設定します。

        Parameters
        ----------
        minutes : float
            何分タイマーを設定するかです。
            小数点を含めることが可能です。
        content : str, optional
            タイマー終了時に送信するメッセージです。
            指定しなかった場合は実行者へのメンションを送信します。

        Notes
        -----
        同時に一つまでしか動かすことができません。
        既に動かしている際にタイマーを設定した場合はその既に動いているタイマーが無効になります。

        Aliases
        -------
        t, タイマー

        !lang en
        --------
        Sets the timer.

        Parameters
        ----------
        minutes : float
            The number of minutes to set the timer.
            Decimal points can be included.
        content : str, optional
            The message to be sent when the timer ends.
            If not specified, it will send a message to the executor.

        Notes
        -----
        You can only run one timer at a time.
        If a timer is set while another timer is already running, the already running timer will be disabled.

        Aliases
        -------
        t"""
        self.timers[ctx.author.id] = Timer(
            ctx.channel, ctx.author, content, content is None, 60 * minutes + time()
        )
        await ctx.reply("タイマーを設定しました。")

    @tasks.loop(seconds=1)
    async def timer_processer(self):
        for user_id, timer in list(self.timers.items()):
            if await timer.process():
                del self.timers[user_id]

    def cog_unload(self):
        self.timer_processer.cancel()


async def setup(bot):
    await bot.add_cog(Watch(bot))
