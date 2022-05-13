# Free RT - Github
from discord.ext import commands


class Github(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.github_url = "https://api.github.com/repos/free-RT/rt-bot/issues"
        self.github_token = bot.secret.get("github", "")

    @commands.group(name="github")
    async def github(self, ctx):
        if ctx.invoked_subcommand:
            return await ctx.send("使い方が間違っています")

    @github.command(name="issue")
    async def issue(self, ctx, title, *, description):
        title = title + f"{ctx.author.name} ({ctx.author.id})"
        data = {
            "title": title,
            "body": description,
        }
        headers = {
            "Authorization": "Bearer {}".format(self.github_token)
        }
        async with self.bot.session.post(self.github_url, data=data, headers=headers):
            await ctx.send("issueを登録しました")


async def setup(bot):
    await bot.add_cog(Github(bot))
