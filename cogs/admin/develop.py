# free RT - Feature for Developers

from discord.ext import commands

from util import RT


class Develop(commands.Cog):

    def __init__(self, bot: RT):
        self.bot = bot

    @commands.group(
        extras={
            "headding": {"ja": "管理者用のコマンドです。", "en": "Only for developers command."},
            "parent": "Admin"
        }
    )
    @commands.is_owner()
    async def develop(self, ctx):
        """!lang ja
        --------
        管理者専用のコマンドです。sub_commands: reload_help, command_log

        !lang en
        --------
        Command for developers only. sub_commands: reload_help, command_log"""
        if ctx.invoked_subcommand is None:
            return await ctx.send("使用方法が違います。")

    @develop.command()
    async def reload_help(self, ctx, command_name=None):
        if command_name is None:
            for c in self.bot.commands:
                await self.bot.cogs["DocHelp"].on_command_add(c)
            await ctx.send("全コマンドのhelp読み込み完了")
        else:
            for c in [self.bot.get_command(co) for co in command_name.split()]:
                await self.bot.cogs["DocHelp"].on_command_add(c)
            await ctx.send(f"{', '.join(command_name.split())}のhelp読み込み完了")

    @develop.command(
        extras={
            "headding": {"ja": "直近1分間のコマンド実行ログを見ます。", "en": "View commands logs."}
        }
    )
    @commands.is_owner()
    async def command_logs(self, ctx, mode=None):
        """!lang ja
        --------
        直近1分間のコマンド実行ログを見ることができます。また、実行ログのループ操作もできます。

        Parameters
        ----------
        mode: startやstop、restartなど
            logging_loop.○○の○○に入れられる文字列を入れて下さい。

        Warnings
        --------
        もちろん実行は管理者専用です。

        !lang en
        --------
        View command logs. Also it can control loop of logs.

        Parameters
        ----------
        mode: start/stop, or restart
            Put the string which can be put in logging_loop.●●.

        Warnings
        --------
        Of cource it can only be used by admin.
        """
        if mode:
            getattr(self.bot.cogs["SystemLog"].logging_loop, mode)()
            await ctx.message.add_reaction("✅")
        elif len(self.bot.cogs["SystemLog"].names) != 0:
            await ctx.reply(embed=self.bot.cogs["SystemLog"]._make_embed())
        else:
            await ctx.reply("ログ無し。")

    @develop.command(
        extras={"headding": {"ja": "言語データを再読込します。",
                             "en": "Reload language data."},
                "parent": "Admin"})
    async def reload_language(self, ctx):
        """言語データを再読込します。"""
        await ctx.typing()
        await self.bot.cogs["Language"].update_language()
        await ctx.reply("Ok")


async def setup(bot):
    await bot.add_cog(Develop(bot))
