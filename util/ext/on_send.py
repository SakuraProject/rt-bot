"""# OnSend
`channel.send(...)`などの実行時に自分の好きなキーワード引数を登録したりする。  
というようなことができるように`on_send`というイベントを作るエクステンションです。  
正確にはdiscord.pyのイベントではありませんので注意。  
なのでこれを使用すれば引数のcontentにeveryoneがあるなら削除したものに引数を置き換えるなどのことが可能です。  
引数から言語名を指定して別の言語にcontentを置き換えるなどが有効的な使用例ですね。

## 使用方法
使えるイベントは`on_send`と`on_edit`です。
### 有効化
`bot.load_extension("util.ext.on_send")`で有効化することができます。  
また`util.setup`でもできます。
### イベント追加/削除
追加：`bot.cogs["OnSend"].add_event(コルーチン関数, イベント名)`
削除：`bot.cogs["OnSend"].remove_event(コルーチン関数, イベント名)`
### イベントのコルーチン関数
```python
async def on_send(channel, *args, **kwargs):
    return args, kwargs
```

## 使用例
```python
bot.load_extension("util.ext.on_send")

async def on_send(channel, *args, **kwargs):
    # もし送信するのにembedがあればembedのフッターにテキストをつける。
    embed = kwargs.get("embed")
    if embed is not None:
        if embed.footer.text is discord.Embed.Empty:
            embed.set_footer(text="なにかあれば`!help`を実行！")
        kwargs["embed"] = embed
    return args, kwargs

bot.cogs["OnSend"].add_event(on_send)
```"""

from typing import Callable, Optional

from discord.ext import commands
import discord

from functools import wraps
from copy import copy


class OnSend(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.events = {
            "on_send": [],
            "on_edit": [],
            "on_webhook_send": [],
            "on_webhook_message_edit": [],
            "on_interaction_response": [],
            "on_interaction_response_edit": []
        }
        self._dpy_injection()

    def wrap_send(self, coro, event_name="on_send"):
        default = copy(coro)

        @wraps(default)
        async def new(ir, *args, **kwargs):
            args, kwargs = await self._run_event(
                event_name, ir, *args, **kwargs
            )
            return await default(ir, *args, **kwargs)            
        return new

    async def _run_event(self, event_name: str, arg, *args, **kwargs):
        # イベントを実行する。
        for coro in self.events[event_name]:
            try:
                args, kwargs = await coro(arg, *args, **kwargs)
            except Exception as e:
                print(f"Error on `on_send`, {coro.__name__}:")
                raise e
                break
        return args, kwargs

    def _dpy_injection(self):
        default_send = copy(discord.abc.Messageable.send)
        default_edit = copy(discord.Message.edit)

        if hasattr(discord.abc.Messageable, "webhook_send"):
            default_webhook_send = copy(discord.abc.Messageable.webhook_send)
        else:
            default_webhook_send = None

        async def new_send(channel, *args, **kwargs):
            args, kwargs = await self._run_event("on_send", channel, *args, **kwargs)
            message = await default_send(
                channel.channel if isinstance(channel, commands.Context) else channel,
                *args, **kwargs
            )
            self.bot.dispatch("sended", message, args, kwargs)
            return message

        if default_webhook_send:
            async def new_webhook_send(channel, *args, **kwargs):
                args, kwargs = await self._run_event(
                    "on_webhook_send", channel, *args, **kwargs)
                message = await default_webhook_send(
                    channel.channel if isinstance(channel, commands.Context) else channel,
                    *args, **kwargs
                )
                self.bot.dispatch("webhook_sended", message, args, kwargs)
                return message

        async def new_edit(message, *args, **kwargs):
            args, kwargs = await self._run_event("on_edit", message, *args, **kwargs)
            message = await default_edit(message, *args, **kwargs)
            self.bot.dispatch("edited", message, args, kwargs)
            return message

        discord.Webhook.edit_message = self.wrap_send(
            discord.Webhook.edit_message, "on_webhook_message_edit"
        )
        discord.InteractionResponse.send_message = self.wrap_send(
            discord.InteractionResponse.send_message, "on_send"
        )
        discord.InteractionResponse.edit_message = self.wrap_send(
            discord.InteractionResponse.edit_message, "on_edit"
        )
        discord.Interaction.edit_original_message = self.wrap_send(
            discord.Interaction.edit_original_message, "on_edit"
        )

        discord.abc.Messageable.send = new_send
        discord.Message.edit = new_edit
        if default_webhook_send:
            discord.abc.Messageable.webhook_send = new_webhook_send

    def add_event(self, coro: Callable, event_name: Optional[str] = None,
                  first: bool = False) -> None:
        """send時に呼び出して欲しいコルーチン関数を登録します。  
        登録したコルーチン関数は`送信対象のチャンネル, *args, **kwargs`の引数が渡されます。  
        そして`args, kwargs`を返却しなければなりません。  
        この時`args, kwargs`の値を変えることでsendの引数ができます。

        Parameters
        ----------
        coro : Callable
            コルーチン関数です。
        event_name : str, optional
            イベント名です。  
            もし指定されなかった場合はcoroの名前が使用されます。
        first : bool, default False
            一番最初に実行されるようにするかどうかです。  
            複数のイベントがこれをTrueとする場合は一番になれないのでご注意！  
            (この場合は`bot.cogs["OnSend"].events`から手動で変更を加える必要がありますねえ。)"""
        event_name = event_name if event_name else coro.__name__
        if first and self.events:
            self.events[event_name] = [coro] + self.events[event_name][1:]
        else:
            self.events[event_name].append(coro)

    def remove_event(self, coro: Callable, event_name: Optional[str]):
        """OnSend.add_eventで登録したコルーチン関数を削除します。

        Parameters
        ----------
        coro : Callable
            登録したコルーチン関数です。
        event_name : str, optional
            イベント名です。
            指定されなかった場合はcoroの名前が使用されます。"""
        event_name = event_name if event_name else coro.__name__
        self.events[event_name].remove(coro)


async def setup(bot):
    await bot.add_cog(OnSend(bot))
