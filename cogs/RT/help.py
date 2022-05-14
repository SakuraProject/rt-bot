# Free RT - Help

from typing import Tuple, List

from discord.ext import commands, tasks
import discord

from util.page import EmbedPage
from util.ext import componesy
from util import RT


class Help(commands.Cog):

    CATEGORIES = {
        "bot": "RT",
        "server-tool": "ServerTool",
        "server-panel": "ServerPanel",
        "server-safety": "ServerSafety",
        "server-useful": "ServerUseful",
        "entertainment": "Entertainment",
        "individual": "Individual",
        "chplugin": "ChannelPlugin",
        "music": "Music",
        "other": "Other"
    }
    CATEGORY_JA = {
        "ServerTool": "サーバーツール",
        "ServerPanel": "サーバーパネル",
        "ServerSafety": "サーバー安全",
        "ServerUseful": "サーバー便利",
        "Entertainment": "娯楽",
        "Individual": "個人",
        "ChannelPlugin": "チャンネルプラグイン",
        "Music": "音楽",
        "Other": "その他"
    }

    def __init__(self, bot: RT):
        self.bot = bot
        self.update_help.start()
        self.bot.backend = False

    async def update_help_web(self):
        "ウェブのヘルプを更新します。"
        async with self.bot.session.post(
            f"{self.bot.get_url()}/api/help/update",
            json=self.bot.cogs["DocHelp"].data
        ) as r:
            self.bot.print("[HelpUpdater]", await r.json())

    @tasks.loop(seconds=30)
    async def update_help(self):
        try:
            async with self.bot.session.get(
                f"{self.bot.get_url()}/api/ping"
            ) as r:
                if (await r.text()) == "pong":
                    self.bot.dispatch("update_api")
        except Exception:
            self.bot.backend = False
        else:
            self.bot.backend = True

    @commands.Cog.listener()
    async def on_update_api(self):
        await self.update_help_web()

    def cog_unload(self):
        self.update_help.cancel()

    def search(self, word: str, lang: str) -> Tuple[str, str, List[Tuple[str, str]], List[Tuple[str, str]]]:
        # 指定された言葉で検索またはヘルプの取得を行う関数です。
        c, category, perfect, on_name, on_doc = False, "", "", [], []
        for category_name in self.help:
            if category_name == word:
                category = word
                break
            perfect = self.help[category_name].get(word, {lang: ["", ""]})[lang][1]
            if perfect == "":
                for cmd in self.help[category_name]:
                    if word in cmd:
                        on_name.append((category_name, cmd))
                    if len(self.help[category_name][cmd][lang]) >= 2:
                        if word in self.help[category_name][cmd][lang][1]:
                            on_doc.append((category_name, cmd))
            else:
                c = category_name
                break
        return c, category, perfect, on_name, on_doc

    async def on_select(self, select, interaction):
        # カテゴリー選択がされたら。
        ctx = await self.bot.get_context(interaction.message)
        if interaction.message.content:
            user = interaction.message.guild.get_member(
                int(interaction.message.content
                    .replace("<@", "").replace(">", "").replace("!", ""))
            )
        elif interaction.message.reference:
            user = interaction.message.reference.cached_message.author
        else:
            user = interaction.user

        if (select.values and select.values[0] != "None" and user
                and user.id == interaction.user.id):
            # 選択されたものを引数としてdhelpのコマンドを実行する。
            ctx.author = user
            ctx.rt = 1
            await self._help(ctx, select.values[0], interaction)

    def get_view_args(self, lang, category):
        # 作るViewのデータを取得するための関数です。
        if category is None:
            options = [discord.SelectOption(label="...", value="None")]
            placeholder = "..."
        else:
            options = [
                discord.SelectOption(
                    label=cmd, value=cmd,
                    description=self.help[category][cmd][lang][0]
                ) for cmd in self.help[category]
                if len(self.help[category][cmd][lang]) >= 2 and cmd
            ]
            placeholder = "コマンド選択" if lang == "ja" else "Command"
        return [
            ("Select", self.on_select, {
                "options": [
                    discord.SelectOption(
                        label=(
                            self.CATEGORY_JA.get(category, category)
                            if lang == "ja" else category
                        ), value=category
                    ) for category in self.help
                    if category
                ],
                "placeholder": "カテゴリー選択" if lang == "ja" else "Category"
            }),
            ("Select", self.on_select, {
                "options": options, "placeholder": placeholder
            })
        ]

    def make_view(self, user, lang, category=None) -> discord.ui.View:
        # Viewを作るための関数です。
        view = componesy.View("HelpView", timeout=60)
        for _, func, kwargs in self.get_view_args(lang, category):
            view.add_item("Select", func, **kwargs)
        return view.get_view()

    async def _help(self, ctx, word, interaction=None):
        self.help = self.bot.cogs["DocHelp"].data
        lang = self.bot.cogs["Language"].get(ctx.author.id)
        edit = hasattr(ctx, "rt")
        reply = True

        if word is None:
            # もしカテゴリー一覧を表示すればいいだけなら。
            url = "http://0.0.0.0" if self.bot.test else "https://free-rt.com/help.html"
            embed = discord.Embed(
                title={
                    "ja": "Help - カテゴリー選択", "en": "Help - Category Select"
                },
                description={
                    "ja": f"カテゴリーを選択するとそのカテゴリーにあるコマンドが表示されます。\nまたこちらからも見れます：{url}"
                          "\n[こちら](https://rt-team.github.io/ja/notes/help)を見るとヘルプをよく理解できるようになれるかもしれません。"
                          "そしてスラッシュコマンドは少し特殊なので[こちら](https://free-rt.github.io/notes/slash_table)を確認してください。\n"
                          "Free RTを使用した場合は[利用規約](https://free-rt.com/terms.html)に同意したことになります。\n"
                          "また、プライバシーポリシーは[こちら](https://free-rt.com/privacy.html)から確認できます。",
                    "en": f"Selecting a category will show you the commands in that category. \nYou can also see them here: {url}\n"
                          "You may be able to understand the help better by looking at [here](https://free-rt.github.io/en/notes/help).\n"
                          "By using Free RT, you agree to the [Terms of Use](https://free-rt.com/terms.html).\n"
                          "You can also view our privacy policy at [here](https://free-rt.com/privacy.html)."
                }, color=self.bot.colors["normal"]
            )
            view = self.make_view(
                getattr(interaction, "user", None) or ctx.author, lang
            )
            await ctx.reply(embed=embed, view=view)
        else:
            c, category, perfect, on_name, on_doc = self.search(word, lang)

            if category:
                # もしカテゴリー名が一致したなら。
                description = "\n".join(
                    f"`{cmd}` {self.help[category][cmd][lang][0]}"
                    for cmd in self.help[category]
                    if len(self.help[category][cmd][lang]) >= 2
                )
                embed = discord.Embed(
                    title=f"Help - {word}",
                    description=description,
                    color=self.bot.colors["normal"]
                )
                view = self.make_view(
                    getattr(interaction, "user", None) or ctx.author,
                    lang, category
                )
                kwargs = {"embed": embed, "view": view}
            elif perfect:
                # もしコマンド名が一致したなら。
                user = getattr(interaction, "user", None) or ctx.author
                embeds = EmbedPage(data=self.bot.cogs["DocHelp"].convert_embed(
                    word, perfect, color=self.bot.colors["normal"]
                ))
                edit, reply = False, not bool(interaction)
                if not reply:
                    await ctx.message.delete()
                if len(embeds.data) == 1:
                    kwargs = {"embed": embeds.data[0], "view": self.make_view(user, lang, c),
                              "target": user.id}
                    del embeds
                else:
                    for _, callback, kwargs in self.get_view_args(lang, c):
                        async def new(self, interaction):
                            return await callback(self, interaction)
                        embeds.add_item(
                            type(
                                "HelpSelector", (discord.ui.Select,),
                                {"callback": new}
                            )(**kwargs)
                        )
                        del new
                    kwargs = {"embed": embeds.data[0], "view": embeds, "target": user.id}
            else:
                # もし何も一致しないなら検索結果を表示する。
                embed = discord.Embed(
                    title="検索結果", color=self.bot.colors["normal"]
                )
                for name, value in (("名前部分一致", on_name), ("説明部分一致", on_doc)):
                    embed.add_field(
                        name=name,
                        value=("\n".join(
                            f"`{n}` {self.help[category][n][lang][0]}"
                            for category, n in value)
                            if value else "見つかりませんでした。")
                    )
                kwargs = {"embed": embed}

            if edit:
                kwargs["target"] = ctx.author.id
                await ctx.message.edit(**kwargs)
            elif reply:
                await ctx.reply(**kwargs)
            else:
                await ctx.send(interaction.user.mention, **kwargs)

    @commands.command(
        name="help", aliases=["h", "Help_me,_ERINNNNNN!!", "たすけて！"],
        extras={
            "headding": {"ja": "Helpを表示します。",
                         "en": "Get help."},
            "parent": "RT"
        }, slash_command=True, description="ヘルプを表示します。"
    )
    @commands.cooldown(1, 3, commands.BucketType.user)
    async def dhelp(
        self, ctx, *, word=None
    ):
        """!lang ja
        --------
        コマンドの使い方が載っているヘルプを表示します。  
        また、[ここ](https://free-rt.github.io/notes/help)を見るとコマンドの見方がよくわかるかもしれません。

        Parameters
        ----------
        word : コマンド名/検索ワード, optional
            表示したいヘルプのコマンド名です。  
            コマンド名ではない言葉が指定された場合は検索します。

        Aliases
        -------
        `h`, `たすけて！`, `Help_me,_ERINNNNNN!!`

        !lang en
        --------
        Displays a help page with information on how to use the command.

        Parameters
        ----------
        word : command name/search word, optional
            The command name of the help to be displayed.  
            If a word that is not a command name is specified, a search will be performed.

        Aliases
        -------
        `h`"""
        await self._help(ctx, word)


async def setup(bot):
    await bot.add_cog(Help(bot))
