"""`discord.ui.View`を簡単に作るためのものです。"""

from discord.ext import commands
import discord

from typing import Union, Type, List, Dict, Callable
from functools import wraps
from time import time


# 作ったViewやItemは全てここに入れる。次同じViewを作らないようにするため。
views: Dict[str, Type[discord.ui.View]] = {}
items: Dict[str, Type[discord.ui.Item]] = {}


def _if_not_exists_view(func):
    # もしviewsに既にあるviewだったら実行しないようにするためのデコレータ。
    @wraps(func)
    def new_func(self, *args, **kwargs):
        if self.name not in views:
            return func(self, *args, **kwargs)
    return new_func


class View:
    """`discord.ui.View`を簡単に作れるクラスです。  
    このクラスをそのままsendの引数のviewに渡す場合は`bot.load_extension("util.ext.componesy")`を実行する必要があります。
    free RT: componesyCogは使用しないでください。「そのまま実行できる」状態を解除したいと考えています。"""
    def __init__(self, name: str, *args, **kwargs):
        self.name: str = name
        self.items: List[Callable] = []
        self.instance_items: List[Type[discord.ui.Item]] = []
        self._args, self._kwargs = args, kwargs
        self._util = True

    def add_item(self, item: Union[Callable, Type[discord.ui.Item], str], callback: Callable = None, **kwargs):
        """Viewにアイテムを追加します。  

        Notes
        -----
        追加することのできるアイテムは`discord.ui`にあるものです。  
        例：`button`, `select`

        Warnings
        --------
        アイテムに`discord.ui.button`や`discord.ui.select`のようなデコレータを設定した場合一度設定したら次設定できません。(設定しようとしても無視されます。)  
        そのため実行の度に変わるものを使うアイテムを追加したい場合は、`discord.ui.Button`や`discord.ui.Select`などの`discord.ui.Item`を継承したクラスの方を使いましょう。  
        そして`discord.ui.Item`を継承したクラスの場合それは作ったViewを`discord.ui.View`に変換してそれをインスタンス化したあとに追加されます。  
        ですので`discord.ui.button`などのようなデコレータで追加したアイテムの後ろの位置に来ます。

        Parameters
        ----------
        item : Union[Callable, Type[discord.ui.Item], str]
            追加するアイテムです。
        callback : Callable = None
            追加するアイテムに設定するコールバックです。  
            もしアイテムを`discord.ui.button`などのデコレータにした場合は、そのコールバックが呼ばれる際にviewとそのアイテムとinteractionが渡されます。  
            もしアイテムを`discord.ui.Button`などのクラスにした場合は、そのコールバックが呼ばれる際にそのアイテムとinteractionが渡されます。
        **kwargs : dict
            そのアイテムに渡すキーワード引数です。  
            例：`label="このボタンは押さないでね。"`"""
        if isinstance(item, str):
            if item == "link_button":
                item = discord.ui.Button
            else:
                item = getattr(discord.ui, item)

        if callback:
            if getattr(callback, "__self__", None) is None:
                new_callback = callback
            else:
                # もしクラスのメソッドならViewを継承したクラスに設定できないのでラップする。
                @wraps(callback)
                async def new_callback(*args, _original_callback=callback, **kwargs):
                    return await _original_callback(*args, **kwargs)

        if item.__name__ in ("Button", "Select", "Item"):
            # もし`discord.ui.Button`などの`discord.ui.Item`を継承したものなら。
            # そのitemを継承したクラスを作りもしcallbackが指定されているのならそのcallbackをそのクラスに入れる。
            item_name = self.name + str(time()).replace(".", "A")
            if item_name not in items:
                # 次作らないようにするために保存しておく。
                items[item_name] = type(
                    item_name, (item,),
                    {"callback": new_callback} if callback else {}
                )
            self.instance_items.append(items[item_name](**kwargs))
        elif item.__name__ in ("button", "select"):
            # もし`discord.ui.button`などのデコレータをなら。
            if self.name not in views:
                # 既に作られているViewならこれを作らない。
                # コールバックにその指定されたデコレータを手動でつける。
                self.items.append(item(**kwargs)(new_callback))
        else:
            raise ValueError("引数itemは`discord.ui.Item`を継承したものまたは`discord.ui.button`などのデコレータである必要があります。"
                             + "もし文字列を渡した場合は`discord.ui.<渡した文字列>`のようにして自動で取得されます。")

    def make_view(self) -> Type[discord.ui.View]:
        """Viewを`discord.ui.View`に変換して取得します。  
        普通はこれを使いません。"""
        if self.name not in views:
            # まだ作ってないViewならViewを作る
            view = type(
                self.name, (discord.ui.View,),
                {callback.__name__: callback for callback in self.items}
            )
            views[self.name] = view
        return views[self.name]

    def get_view(self) -> object:
        """Viewをインスタンス化済みの`discord.ui.View`にして取得します。  
        これを使ってviewを取得してからそれをsendに渡しましょう。"""
        view = self.make_view()(*self._args, **self._kwargs)
        # EasyView.add_itemで追加された`discord.ui.Item`を継承したアイテムを追加する。
        for item in self.instance_items:
            view.add_item(item)
        return view

    def __call__(self):
        return self.get_view()


class Componesy(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        if "OnSend" not in self.bot.cogs:
            self.bot.load_extension("util.ext.on_send")
        for name in ("on_send", "on_edit", "on_interaction_response"):
            self.bot.cogs["OnSend"].add_event(self._new_send, name)

    async def _new_send(self, channel, *args, **kwargs):
        # 何かしらの送信時にキーワード引数のviewがあるなら
        if (view := kwargs.get("view")):
            # Componesyによるものなら。
            if getattr(view, "_util", False):
                # インスタンス済みのdiscord.ui.Viewにする。
                kwargs["view"] = view.get_view()
        return args, kwargs

    async def test_interaction(self, button, interaction):
        await interaction.response.send_message("Pushed button.")

    async def test_count(self, view, button, interaction):
        button.label = str(int(button.label) + 1)
        await interaction.message.edit(view=view)

    @commands.command(name="_componesy_test")
    async def test(self, ctx):
        view = View("TestView")
        view.add_item("Button", self.test_interaction, label="Push me!")
        view.add_item("button", self.test_count, label="0")
        await ctx.reply("test", view=view)


def setup(bot):
    bot.add_cog(Componesy(bot))
