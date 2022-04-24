# free RT - Feature for Developers

from discord.ext import commands

from util import RT

from ycmd.ycmd import CMD

from ycmd.ClassData import ClassData 

class Develop(commands.Cog):
    
    def __init__(self, bot: RT):
        self.bot = bot
    
    @commands.group(
        extras={
            "headding":{"ja":"管理者用のコマンドです。", "en":"Only for developers command."},
            "parent":"Admin"
        }
    )
    @commands.is_owner()
    async def develop(self, ctx):
        if ctx.invoked_subcommand is None:
            return await ctx.send("使用方法が違います。")
    
    @develop.command()
    async def reload_help(self, ctx, command_name = None):
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
            "headding":{"ja":"直近1分間のコマンド実行ログを見ます。", "en":"View commands logs."}
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
            await ctx.message.add_reaction("?")
        elif len(self.bot.cogs["SystemLog"].names) != 0:
            await ctx.reply(embed=self.bot.cogs["SystemLog"]._make_embed())
        else:
            await ctx.reply("ログ無し。")



    @develop.command(
        extras={
            "headding":{"ja":"ycmdコードを実行します。(bot管理者専用です)", "en":"run ycmd code (it's bot owner only"}
        }
    )
    @commands.is_owner()
    async def ycmd(self, ctx, *, code):
        cmd = CMD()
        cmd.var["ctx"]=ClassData(ctx)
        cmd.var["bot"]=ClassData(self.bot)
        cmd.var["commandclass"]=ClassData(self)
        self.bot.loop.create_task(cmd.cmdrun(code))

def setup(bot):
    bot.add_cog(Develop(bot))
