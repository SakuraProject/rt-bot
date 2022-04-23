# RT Util - Sec URL

from typing import TypedDict

from aiohttp import ClientSession
from ujson import loads


HEADERS = {
    "Connection": "keep-alive",
    "sec-ch-ua": '"Microsoft Edge";v="95", "Chromium";v="95", ";Not A Brand";v="99"',
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "X-Requested-With": "XMLHttpRequest",
    "sec-ch-ua-mobile": "?0",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/95.0.1020.40",
    "sec-ch-ua-platform": '"macOS"',
    "Origin": "https://securl.nu",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
    "Referer": "https://securl.nu/",
    "Accept-Language": "ja,en;q=0.9,en-GB;q=0.8,en-US;q=0.7",
}


class SecURLData(TypedDict, total=False):
    "SecURLのURLチェックの結果のデータの型です。"
    status: int
    imgWidth: int
    imgHeight: int
    reqURL: str
    resURL: str
    title: str
    anchors: list
    viruses: list
    blackList: list
    annoyUrl: str
    img: str
    capturedDate: str


async def check(
    session: ClientSession, url: str, wait_time: int = 1,
    browser_width: int = 965, browser_height: int = 683,
    headers: dict = HEADERS
) -> SecURLData:
    """渡されたURLをSecURLでチェックします。
    Parameters
    ----------
    session : aiohttp.ClientSession
        通信に使うsessionです。
    url : str
        チェックするURLです。
    wait_time : int, default 1
        どれだけ待つかです。
    browser_width : int, default 965
        ブラウザのサイズです。
    browser_height : int, default 683
        ブラウザのサイズです。
    headers : dict, default HEADERS
        通信に使うヘッダーです。通常は変更しなくても大丈夫です。
    Raises
    ------
    ValueError : URLにアクセスできなかった際などの失敗時に発生します。"""
    async with session.post(
        "https://securl.nu/jx/get_page_jx.php", data={
            "url": url, 'waitTime': str(wait_time),
            'browserWidth': str(browser_width),
            'browserHeight': str(browser_height), 'from': ''
        }, headers=headers
    ) as r:
        return loads(await r.text())


def get_capture(
    data: SecURLData, full: bool = False
) -> str:
    """渡されたデータにある`img`のデータからURLを作ります。
    Parameters
    ----------
    data : SecURLData
        SecURLから返された辞書データです。
    full : bool
        上から一番下までの写真のURLを返すかどうかです。"""
    return (
        f"https://securl.nu/save_local_captured.php?key={data['img'][10:-4]}"
        if full else f"{HEADERS['Origin']}{data['img']}"
    )
