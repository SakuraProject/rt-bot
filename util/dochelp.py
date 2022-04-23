"""自動ドキュメンテーションヘルプ管理  
コマンドフレームワークで定義したコマンドのコルーチン関数にあるドキュメンテーションから、ヘルプリストを自動で生成するためのエクステンションです。  
ヘルプメッセージの管理がとても楽になります。  
`bot.load_extension("util.dochelp")`で有効化することができます。  
また`util.setup`でも有効化できます。  
これを読み込む場合は`on_command_add`が自動で読み込まれるのでこれを読み込まないでください。
### 書き込み方法
下のExamplesのようにすれば良いです。  
ですがもし親コマンドのいないコマンドのヘルプの場合は以下のようにカテゴリーを指定してください。
```
!parent カテゴリー名
-------
```
これで自動でカテゴリーが作成されそのカテゴリーにそのコマンドのヘルプが書き込まれます。  
親コマンドのいないコマンドとはグループコマンドやpingコマンドなどの他と関連するコマンドのないコマンドのことです。
### 出力されたヘルプ
`bot.cogs["DocHelp"].data`から参照することができます。  
日本語で開く例：`bot.cogs["DocHelp"].data["カテゴリーX"]["えっくすふぁいる"]["ja"]`  
言語については下のNotesをみてください。

Notes
-----
### 読み込みについて
このエクステンションを読み込むのは他のエクステンションを読み込む前にしましょう。  
そうしないとこのエクステンションを読み込む前に読み込まれたコマンドのヘルプが登録されません。  
それと`util.ext.on_command_add`のエクステンションが読み込まれていない場合は自動でこれが読み込まれます。
### ヘルプの言語について
ヘルプの言語は複数設定することができます。  
下のExamplesにもありますが`!lang ja`のように設定をすることができます。  
書き方は`!lang 言語名`です。  
デフォルトは`ja`でこれを書かない場合は`ja`となります。
### インデントについて
インデントはデフォルトでは空白四つでなければ対応していません。  
ですがこの設定は以下のように変更することができます。  
インデントの数の設定：`bot.cogs["DocHelp"].indent: int` (デフォルトが`4`)  
インデントの文字設定：`bot.cogs["DocHelp"].indent_type: str` (デフォルトが`" "`)
### 項目の交換に使う文字列について
`Parameters`などの項目名の交換に使う文字列は変更することが可能です。  
`bot.cogs["DocHelp"].dp`にドキュメンテーションをマークダウンに変換するためのクラスのインスタンスがあります。  
そのインスタンスに`HEADDINGS`と言う属性があります。  
ここに辞書形式で項目名の交換に使う文字列があります。  
これを自分の好きなやつと交換しましょう。

Examples
--------
@bot.command(name="そうだよ")
async def soudayo(ctx, mode="便乗"):
    \"\"\"
    !lang ja
    --------
    このコマンドはそうだよを作るコマンドです。

    Parameters
    ----------
    mode : str, default 便乗
        そうだよの後ろにくる括弧に入れるものです。
        デフォルトは便乗です。

    Examples
    --------
    そうだよを言わせます。
    `!そうだよ` -> そうだよ(便乗)
    \"\"\"
    await ctx.reply(f"そうだよ({mode})")

# 上のコマンドにあるドキュメンテーションがヘルプリストに自動で追加されます。"""

from __future__ import annotations

from collections.abc import Callable

from inspect import ismethod
from functools import wraps

from discord.ext import commands
import discord

from aiofiles import open as async_open
from ujson import loads, dumps

from .docparser import DocParser
from data import PERMISSION_TEXTS


def make_permission_help(
    perms: dict[str, bool], option: Callable[[str], str] = lambda x: x
) -> str:
    "権限のヘルプを作ります。"
    return f'`{"`, `".join(option(perm) for perm, is_enable in perms.items() if is_enable)}`'


# 権限一覧をヘルプに追加するように改造する。
def make_new_hp(original):
    @wraps(original)
    def new_hp(**perms):
        decorator = original(**perms)
        @wraps(decorator)
        def new_decorator(func):
            if func.__doc__ and "!lang en" in func.__doc__:
                func.__doc__ = func.__doc__.replace("!lang en", f"Permissions\n        -----------\n        {make_permission_help(perms, lambda perm: PERMISSION_TEXTS.get(perm, perm))}\n\n        !lang en")
                func.__doc__ += f"\n\n        Permissions\n        -----------\n        {make_permission_help(perms)}"
                if func.__name__ == "captcha":
                    print(func.__doc__)
            return decorator(func)
        return new_decorator
    return new_hp
commands.has_permissions = make_new_hp(commands.has_permissions)
commands.has_guild_permissions = make_new_hp(commands.has_guild_permissions)


class DocHelp(commands.Cog):

    ALLOW_LANGUAGES = ("ja", "en")

    def __init__(self, bot):
        self.bot = bot
        self.data: dict = {}
        self.tree: dict[str, list[str]] = {}
        self.categories: dict[str, str] = {}

        self.dp = DocParser()
        self.indent_type = " "
        self.indent = 4
        self._prefix = None

    async def on_command_add_kari(self, command):
        if hasattr(command, "commands"):
            for cmd in sorted(
                command.commands, key=lambda c: len(c.qualified_name)
            ):
                await self.on_command_add(cmd)
                await self.on_command_add_kari(cmd)
                self.bot.dispatch("command_add", cmd)

    @commands.Cog.listener()
    async def on_full_ready(self):
        self.data, self.tree, self.categories = {}, {}, {}
        for command in self.bot.commands:
            await self.on_command_add(command)
            self.bot.dispatch("command_add", command)
            await self.on_command_add_kari(command)

    def convert_embed(self, command_name: str, doc: str, **kwargs) -> list[discord.Embed]:
        """渡されたコマンド名とヘルプ(マークダウン)をEmbedにします。
        Parameters
        ----------
        command_name : str
            コマンド名です。
        doc : str
            内容です。
        **kwargs : dict
            Embedに渡すキーワード引数です。
        Returns
        -------
        List[discord.Embed]"""
        text, embeds, length = "", [], 0
        make_embed = lambda text: discord.Embed(
            title=f"**{command_name}**", description=text, **kwargs)

        for line in doc.splitlines():
            is_item = line.startswith("## ")
            # Embedやフィールドを作るか作るないか。
            if is_item:
                line = f"\n**{line[3:]}**"
            # 文字列を整える。
            elif line.startswith("### "):
                line = "**#** " + line[4:]
            elif line.endswith("  "):
                line = line[:-2]
            elif line.count("*") > 3 and line[2] != "#":
                line = line.replace("**", "*`", 1).replace("**", "`", 1) + "*"
            length += (now_length := len(line))

            # もしtextの文字数が2000超えてしまうなら新しくEmbedを作る。
            if length > 2000:
                embeds.append(make_embed(text[:-1]))
                text, length = "", now_length

            text += f"{line}\n"

        # fieldが一つでもないとEmbedが作られない、そのためEmbedが空の場合作る。
        if length <= 2000:
            embeds.append(make_embed(text[:-1]))

        return embeds

    def parse(self, command: commands.Command) -> dict:
        # コマンドのドキュメンテーションを辞書に変換します。
        return self.dp.parse(
            command.callback.__doc__,
            first_indent_count=int(bool(ismethod(command.__call__))) + 1,
            indent=self.indent, indent_type=self.indent_type
        )

    @property
    def prefix(self):
        # Botの一番最初にあるプリフィックスを取得します。
        if self._prefix is None:
            self._prefix = self.bot.command_prefix
            if isinstance(self._prefix, (tuple, list)):
                self._prefix = self._prefix[0]
        return self._prefix

    async def on_command_add(self, command, after: bool = False):
        if command.callback.__doc__:
            extras = command.extras if command.extras else {
                "headding": command.__original_kwargs__.get("headding", {})
                    or ({"ja": command.description} if command.description else {}),
                "parent": command.__original_kwargs__.get("category", "Other")
            }
            if extras and extras["headding"] and not after and command.parent is None:
                # ドキュメンテーションをマークダウンにする。
                data = self.parse(command)
                # もしカテゴリーが設定されているならそのカテゴリーコマンドを入れる。
                if (category := extras.get("parent", "Others")) not in self.data:
                    self.data[category] = {}
                # self.treeにカテゴリ名がわかるように保存しておく。
                if command.name not in self.categories:
                    self.categories[command.name] = category
                    self.tree[command.name] = []
                self.data[category][command.name] = {}
                # コマンドのデータを作っていく。
                for lang in data:
                    self.data[category][command.name][lang] = [
                        extras.get("headding", {}).get(lang, "..."),
                        data[lang]
                    ]
            elif (parent := command.root_parent):
                parent = parent.name
                # ドキュメンテーションをマークダウンにする。
                data = self.parse(command)
                # もしグループコマンドの子コマンドなら親コマンドのヘルプに追記する。
                if parent in self.tree:
                    if command.qualified_name not in self.tree[parent]:
                        category = self.categories[parent]

                        for lang in list(self.data[category][parent].keys()):
                            self.data[category][parent][lang][1] += \
                                (f"\n## {self.prefix}{command.qualified_name}\n"
                                 + f"{data.get(lang, data['ja'])}")
                        self.tree[parent].append(command.qualified_name)

    @commands.Cog.listener()
    async def on_command_remove(self, command):
        # もしコマンドが削除されたならそのコマンドのヘルプも削除する。
        # コマンドがグループコマンドではない場合は何もしない。
        name = command if isinstance(command, str) else command.name
        if name in self.categories:
            del self.data[self.categories[name]][name]
            del self.tree[name]

    async def output(self, path: str) -> None:
        """作ったヘルプのデータをjson形式でファイルに出力します。
        
        Parameters
        ----------
        path : str
            出力するファイルのパスです。"""
        async with async_open(path, "w") as f:
            await f.write(dumps(self.data))

    async def input(self, path: str) -> None:
        """util.dochelpが読み込める形式のjsonファイルのヘルプを読み込みます。
        
        Parameters
        ----------
        path : str
            読みこむファイルのパスです。"""
        async with async_open(path, "r") as f:
            self.data.update(loads(await f.read()))

    def add_help(self, category: str, help_name: str, lang: str,
                 headding: str, content: str) -> None:
        """ヘルプを追加します。

        Parameters
        ----------
        category : str
            追加するヘルプのカテゴリーです。
        help_name : str
            追加するヘルプの名前です。  
            大抵コマンド名を入れます。
        lang : str
            言語名です。  
            もし日本語なら`ja`を入れましょう。
        headding : str
            見出しです。
        content : str
            ヘルプの内容です。"""
        if category not in self.data:
            self.data[category] = {}
        if help_name not in self.data[category]:
            self.data[category][help_name] = {}
        self.data[category][help_name][lang] = (headding, content)

    def remove_category(self, category: str) -> None:
        """ヘルプリストのカテゴリーを削除します。

        Parameters
        ----------
        category : str
            削除するカテゴリーです。

        Raises
        ------
        KeyError : カテゴリーが見つからない場合発生します。"""
        del self.data[category]

    def remove_help(self, category: str, help_name: str) -> None:
        """ヘルプリストからヘルプを削除します。

        Parameters
        ----------
        category : str
            削除するヘルプがあるカテゴリーの名前です。
        help_name : str
            削除するヘルプの名前です。

        Raises
        ------
        KeyError : 指定されたカテゴリーまたはヘルプが存在しない際に発生します。"""
        del self.data[category][help_name]


def setup(bot):
    bot.add_cog(DocHelp(bot))
