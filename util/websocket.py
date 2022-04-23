# RT Lib - WebSocket

from typing import (
    TYPE_CHECKING, Callable, Coroutine, TypedDict, Literal, Iterator,
    Union, Optional, Any, Tuple, Dict, overload
)

from discord.ext import commands

from asyncio import Event, sleep, Task
from collections import defaultdict
from traceback import print_exc
from ujson import loads, dumps
from functools import wraps

from websockets import exceptions as wsexceptions
import websockets

if TYPE_CHECKING:
    from .types import RT


WEBSOCKET_URI_BASE = "ws://localhost"


class WebSocketEvent(Event):
    "イベントからのデータの受け渡しを簡単に行うためのクラスです。"

    data: Any = None
    waiting: bool = False

    def set(self, data: Any) -> None:
        "データを設定して`wait`を解除します。"
        self.data = data
        super().set()

    async def wait(self) -> Any:
        "`set`されるまで待ってデータを返します。もし待っている間に接続が切れた場合はエラーが発生します。"
        self.waiting = True
        await super().wait()
        if "ConnectionClosed" in getattr(self.data, "__name__", ""):
            raise self.data
        data = self.data
        self.waiting = False
        self.clear()
        return data

    def clear(self):
        "`set`状態をリセットします。"
        self.data = None
        super().clear()


def _set_websocket_data(func, uri, event_type="on_connect", kwargs={}):
    if not uri.startswith(("ws://", "wss://")):
        uri = f"{WEBSOCKET_URI_BASE}{uri if uri[0] == '/' else f'/{uri}'}"
    func._websocket = (uri, event_type, kwargs)
    return func


EventDecorator = Callable[[Callable], "EventFunction"]


class EventFunction(WebSocketEvent):
    "WebSocketの関数に入れるクラスです。簡単にデータの受け渡しができるようにするためのものです。"

    ws: "WebSocket" = None
    cog: commands.Cog

    def __init__(
        self, func: Callable[..., Coroutine], uri: str, event_type: str, **kwargs
    ):
        _set_websocket_data(self, uri, event_type, kwargs)
        super().__init__()
        self.uri = uri
        self.func = func

    def __call__(self, *args, **kwargs):
        return self.func(self.cog, *args, **kwargs)

    def event(self, event_type: str) -> EventDecorator:
        "イベントを設定します。"
        def decorator(func):
            return wraps(func)(EventFunction(func, self.uri, event_type))
        return decorator

    async def connect(self, pass_connection_failed_error: bool = False) -> Task:
        "WebSocketに接続します。"
        return self.cog.bot.loop.create_task(
            self.ws.connect(pass_connection_failed_error)
        )

    async def close(self, code: str = 1000, reason: str = "") -> None:
        "WebSocketから切断します。(`ws.close`のエイリアス。)"
        return await self.ws.close(code, reason)


@overload
def websocket(
    uri: str, auto_connect: bool = False, reconnect: bool = False,
    log: bool = False, **kwargs
) -> EventDecorator:
    ...


def websocket(
    uri: str, **kwargs
) -> EventDecorator:
    """WebSocket通信を行いたいコルーチン関数に付けるデコレータです。  
    もし`ws://...`を省略した場合は自動で`WEBSOCKET_URI_BASE`(`ws://localhost`)が最初に付けられます。

    Examples
    --------
    ```python
    @websocket("/wstest", auto_connect=False)
    async def ws_test(self, ws: WebSocket, _):
        await ws.send("print", "From bot")
        await ws.send("ping")

    @ws_test.event("ping")
    async def ping(self, _, data: PacketData):
        print("From backend:", data)

    @commands.command()
    async def start(self, ctx: commands.Context):
        await ctx.trigger_typing()
        await self.ws_test.connect()
        data = await self.ping.wait()
        await ctx.reply(f"From backend : {data}")
    ```"""
    def decorator(func: Callable) -> EventFunction:
        return wraps(func)(EventFunction(func, uri, "on_connect", **kwargs))
    return decorator


class ConnectionFailed(Exception):
    "WebSocketで接続が失敗した際に`reconnect`が`False`の際に発生するエラーです。"


PacketData = Union[str, dict]
class Packet(TypedDict):
    "WebSocketで通信するデータの辞書の型です。"
    event_type: str
    data: PacketData


class WebSocket:
    """簡単にWebSocketの通信をするためのクラスです。  
    これを使うなら`websocket`のデコレータをコグの関数に付けてください。"""

    uri: str
    event_handlers: Dict[str, EventFunction]
    cog: commands.Cog
    running: Literal["doing", "ok", "error"] = "doing"
    ws: Optional[websockets.WebSocketClientProtocol] = None

    def __new__(
        cls, cog: commands.Cog, uri: str,
        event_handlers: Dict[str, Callable[..., Coroutine]], log: bool = False,
        auto_connect: bool = False, reconnect: bool = False, **kwargs
    ) -> Tuple["WebSocket", Coroutine]:
        self = super().__new__(cls)
        self.uri, self.event_handlers, self._kwargs = uri, event_handlers, kwargs
        self.cog, self._reconnect, self._log = cog, reconnect, log

        if auto_connect:
            # 自動接続が指定されているなら自動通信を開始する。
            self.task = self.cog.bot.loop.create_task(self.connect(False))

        return self

    def print(self, *args, **kwargs) -> None:
        "ログ出力をします。"
        if self._log:
            self.cog.bot.print(
                f"[{self.cog.__cog_name__}]", f"[WebSocket:{self.uri}]", *args, **kwargs
            )

    async def run_event(
        self, event_type: str, data: PacketData, *args, **kwargs
    ) -> Any:
        "WebSocketに登録されているイベントハンドラを実行します。内部で使用されています。"
        self.event_handlers[event_type].set(data)
        return await self.event_handlers[event_type](self, data, *args, **kwargs)

    async def connect(self, pcfe: bool):
        try:
            return await self._connect(pcfe)
        except Exception:
            print_exc()

    async def _connect(self, pcfe):
        "WebSocketに接続して通信を開始します。"
        while not self.cog.bot.is_closed() and self.running == "doing":
            # 接続を試みて失敗した場合にreconnectがTrueの時のみ三秒後もう一度接続する。
            try:
                self.ws = await websockets.connect(
                    self.uri, **self._kwargs
                )
            except OSError as e:
                if self._reconnect:
                    self.print("Failed to connect to websocket, I will try to reconnect.")
                    await sleep(3)
                    continue
                else:
                    if pcfe:
                        return
                    else:
                        raise ConnectionFailed("WebSocketサーバーに接続できませんでした。")
            else:
                self.print("Connected to websocket")

                # 接続した際にもし「on_connect」があるならそれを実行する。
                if "on_connect" in self.event_handlers:
                    await self.run_event("on_connect", {})

                # メインの通信を開始する。
                while not self.cog.bot.is_closed() and self.running == "doing":
                    data = await self.recv()

                    if data:
                        if data["event_type"] in self.event_handlers:
                            # イベントハンドラを実行してもしデータを返されたならそれを送り返す。
                            if (return_data := await self.run_event(
                                data["event_type"], data["data"])
                            ):
                                await self.send(data["event_type"], return_data)
                        else:
                            # もしイベントが見つからなかったのならWebSocketを切断する。
                            self.print(
                                f"Disconnected from bot because bot gave me an event that dosen't exists : {data['event_type']}"
                            )
                            await self.close(1003, "そのイベントが見つかりませんでした。")

                self.print(f"Finished websocket connection ({self.running})")

                if ((not self.cog.bot.is_closed() or self._reconnect)
                        and self.running != "unload"):
                    await self.close()
                    self.print("I will try to reconnect.")
                    self.running = "doing"
                    await sleep(3)
                else:
                    break

    async def send(self, event_type: str, data: PacketData = "") -> None:
        "データを送信します。"
        await self._wrap_error(
            self.ws.send(dumps({"event_type": event_type, "data": data}))
        )

    async def recv(self) -> Optional[Packet]:
        "データを受信します。もし切断された場合は何も返されません。"
        if (data := await self._wrap_error(self.ws.recv())):
            return loads(data)

    async def _wrap_error(self, coro: Coroutine) -> Any:
        # コルーチンを接続エラーをラップして実行する関数です。
        try:
            data = await coro
        except wsexceptions.ConnectionClosedOK:
            if self.running != "unload":
                self.running = "ok"
        except wsexceptions.ConnectionClosedError:
            if self.running != "unload":
                self.running = "error"
        else:
            return data

    def is_closed(self) -> bool:
        "WebSocketが閉じているかどうかを確認します。"
        return self.running != "doing"

    def _check_error(self, code: int) -> bool:
        return code in (1000, 1001)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        "WebSocket通信を終了します。"
        if code == 4000:
            self.running = "unload"
        else:
            self.running = "ok" if self._check_error(code) else "error"
        if self.ws:
            await self.ws.close(code, reason)
            self.print(f"Disconnected from websocket ({self.running})")
        self.ws = None
        # もし`wait`でイベントを待っている関数があるなら終了させる。
        for func in self.event_handlers.values():
            if func.waiting:
                func.set(getattr(
                    websockets.exceptions,
                    f"ConnectionClosed{'OK' if self._check_error(code) else 'Error'}"
                ))


class WebSocketManager(commands.Cog):
    def __init__(self, bot: "RT"):
        self.bot = bot
        self._websockets = []

    def websockets(self, cog: commands.Cog) -> Iterator[Callable[..., Coroutine]]:
        # コグにあるWebSocketの関数をひとつづつ取り出す。
        for name in dir(cog):
            if hasattr(func := getattr(cog, name), "_websocket"):
                yield func

    @commands.Cog.listener()
    async def on_cog_add(self, cog: commands.Cog):
        # コグが追加された際にwebsocketデコレータが付いている関数をまとめる。
        websockets = defaultdict(dict)
        for func in self.websockets(cog):
            uri, event_type, kwargs = func._websocket
            websockets[uri][event_type] = func
            websockets[uri][event_type].cog = cog
            # キーワード引数があるならそれをコグに保存しておく。
            if kwargs:
                cog.websocket_kwargs = kwargs
        else:
            if not hasattr(cog, "websockets"):
                cog.websockets = {}

            # 見つけたWebSocketの関数の通信を開始する。
            for uri in websockets:
                self.print("Make WebSocket :", uri)
                websocket = WebSocket(
                    cog, uri, websockets[uri],
                    **getattr(cog, "websocket_kwargs", {})
                )
                self._websockets.append(websocket)
                # WebSocketを関数に保存しておく。
                websockets[uri]["on_connect"].ws = websocket
                # コグの関数からWebSocketにアクセスするためにコグに保存しておく。
                cog.websockets[uri] = websocket
            del websockets

    async def _close_websocket(self, websocket: WebSocket) -> None:
        # 渡されたウェブソケットを閉じる。
        if websocket in self._websockets:
            self._websockets.remove(websocket)
            await websocket.close(4000, "コグの削除による切断です。")
            if hasattr(websocket, "task"):
                websocket.task.cancel()
        del websocket

    @commands.Cog.listener()
    async def on_cog_remove(self, cog: commands.Cog):
        # もしコグが削除された際にそのコグにWebSocketの関数があるなら通信を終了させる。
        for func in self.websockets(cog):
            if hasattr(func, "_websocket"):
                await self._close_websocket(cog.websockets[func._websocket[0]])

    @commands.Cog.listener()
    async def on_close(self, _):
        self.bot.print("Closing websockets...")
        for websocket in self._websockets:
            self.bot.loop.create_task(self._close_websocket(websocket))

    def print(self, *args, **kwargs):
        "ログを出力します。"
        self.bot.print("[WebSocketManager]", *args, **kwargs)


def setup(bot):
    bot.add_cog(WebSocketManager(bot))
