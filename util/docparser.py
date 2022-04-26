# Free RT Util - Doc Parser

from typing import Literal, Optional, Union, Callable, Tuple

from inspect import cleandoc


class DocParser:
    """ドキュメントをパースするためのクラスです。"""

    HEADDINGS = {
        "ja": {
            "Parameters": "### コマンドの引数",
            "Notes": "### メモ",
            "Warnings": "### 警告",
            "Examples": "### コマンドの使用例",
            "Raises": "### 起こり得るエラー",
            "Returns": "### 実行結果",
            "See Also": "### 関連事項",
            "Aliases": "### エイリアス",
            "Permissions": "### 権限"
        },
        "en": {
            "Parameters": "### Argments",
            "Notes": "### Note",
            "Warnings": "### Warning",
            "Examples": "### Example",
            "Raises": "### Possible errors",
            "Returns": "### Result",
            "See Also": "### See Also",
            "Aliases": "### Aliases",
            "Permissions": "### Permissions"
        }
    }
    ITEM_REPLACE_TEXTS = {
        "ja": {
            "str": "文字列",
            "int": "整数",
            "float": "小数",
            "bool": "真偽値",
            "optional": "オプション",
            "default": "デフォルト"
        },
        "en": {
            "str": "text",
            "int": "integer",
            "float": "decimal",
            "bool": "boolean"
        }
    }

    def __init__(self):
        self.events = {}

    def _split(self, text: str, target: str = ":") -> Tuple[str, str, int, int]:
        # targetの左と右を分けてtargetの周りにある空白の数を取得する。
        colon_index = text.find(":")
        left, right = text[:colon_index], text[colon_index + 1:]
        del colon_index
        left_count, right_count = 0, 0
        for i in range(len(left)):
            if left[0 - (i + 1)] == " ":
                left_count += 1
            else:
                break
        for char in right:
            if char == " ":
                right_count += 1
            else:
                break
        return (left[:0 - left_count], right[right_count:],
                left_count, right_count)

    def _colon_parser(self, line: str, now_lang: str) -> str:
        # ITEM_REPLACE_TEXTSにある文字列は日本語に置き換える。
        for type_name in self.ITEM_REPLACE_TEXTS[now_lang]:
            if type_name in line:
                line = line.replace(
                    type_name, self.ITEM_REPLACE_TEXTS[now_lang]
                    .get(type_name, type_name)
                )
        # 名前の部分を**で囲む。
        if ":" in line:
            left, right, left_count, right_count = self._split(line)
            return "".join((f"**{left.replace(' ', '')}**{' '*left_count}:",
                            f"{' '*right_count}{right.replace(' ', '')}"))
        else:
            return f"**{line.replace(' ', '')}**"

    def _item_parser(self, line: str, now: dict, before: dict) -> str:
        # 項目に含まれているものを最適なマークダウンに変換するものです。
        if now["item"] in ("Parameters", "Raises", "Returns", "See Also"):
            if (all(char in self.indent_type for char in line[:self.indent])
                    if len(line) >= self.indent else line == ""):
                # 引数の説明。
                return line[self.indent:]
            elif all(char in (" ", "*") for char in line[:-2]):
                return line
            else:
                # 引数の名前と型。
                return self._colon_parser(line, now["lang"]) + "  "
        return line

    def add_event(self, function: Callable, event_name: Optional[str] = None) -> None:
        """`!`から始まる項目をカスタムするためのイベントハンドラを追加します。  
        ドキュメンテーションから引数を渡すなどに使うことができます。

        Parameters
        ----------
        function : Callable
            イベントハンドラの関数です。
        event_name : Optional[str], default None
            イベント名です。  
            `!event_name`となります。

        Examples
        --------
        DocParser.add_event(lambda line, now, before: print("テストじゃん。", line),
                            "This_is_the_test.")"""
        event_name = function.__name__ if event_name is None else event_name
        self.events[event_name] = function

    def remove_event(self, event_name: str) -> None:
        """指定されたイベントを削除します。

        Parameters
        ----------
        event_name : str
            削除するイベントの名前です。"""
        del self.events[event_name]

    def parse(self, doc: str, *, first_indent_count: int = 1, indent: int = 4,
              indent_type: Literal[" ", "\t"] = " ", session_id: Union[str, int] = 0,
              item_parser: Optional[Callable] = None) -> dict:
        """渡されたドキュメンテーションをマークダウンにパースします。

        Parameters
        ----------
        doc : str
            対象のドキュメンテーションです。
        first_indent_count : int, default 1
            ドキュメンテーションの最初にあるインデントの個数です。
        indent : int, default 4
            インデントの空白の数です。
        indent_type : Literal[" ", "\t"], default " "
            インデントに使われているの空白の文字です。
        session_id : Union[str, int], default 0
            イベントでなんのドキュメンテーションで呼び出されたか判別するのに使えるセッションIDです。
        item_parser : Optional[Callable[str, dict, dict]] = None
            項目をパースする際に使う関数です。  
            指定されなかった場合は`DocParser._item_parser`が使用されます。  
            カスタムしたい場合は`DocParser._item_parser`とか見て仕組み覗いて自分で作ろうね。

        Returns
        -------
        dict
            これは言語で分けられてパースしたドキュメンテーションを返すため辞書型となっています。  
            デフォルトの言語は`ja`となっています。""" # noqa
        item_parser = self._item_parser if item_parser is None else item_parser
        self.indent, self.indent_type = indent, indent_type

        text = {"ja": ""}
        before = {
            "line": "",
            "item": ""
        }
        now = {
            "lang": "ja",
            "item": "description",
            "session_id": session_id,
            "code": False
        }

        for line in cleandoc(doc).splitlines():
            if "```" in line:
                now["code"] = not now["code"]

            # パースする。
            if all(char == "-" for char in line) and line != "":
                if before["line"].startswith("!lang "):
                    now["lang"] = before["line"][6:]
                    if now["lang"] not in text:
                        text[now["lang"]] = ""
                    now["item"] = "description"
                elif before["line"].startswith(tuple([f"!{key}" for key in self.events])):
                    blank_index = before["line"].find(" ")
                    if blank_index == -1:
                        item_name = before["line"][1:]
                    else:
                        item_name = before["line"][1:blank_index]
                    write = self.events[item_name](line, now, before)
                    if write:
                        now["item"] = item_name
                    else:
                        now["item"] = "!"
                else:
                    before["item"] = now["item"]
                    now["item"] = before["line"]
                    t = self.HEADDINGS[now["lang"]].get(now["item"], now["item"]) + "\n"
                    text[now["lang"]] += t
            elif (line not in self.HEADDINGS[now["lang"]]
                  and (now["code"] or not line.startswith("!"))
                  and now["item"] != "!"):
                # もし改行のみで空白2個が後ろにないなら改行を空白二個と置き換える。
                if not line.endswith("  ") and not now["code"]:
                    line = line + "  "
                text[now["lang"]] += item_parser(line, now, before) + "\n"
            before["line"] = line

        # 最初と最後に改行があるならそれを削除しておく。
        for key in text:
            if text[key]:
                while text[key]:
                    if text[key][0] == "\n":
                        text[key] = text[key][1:]
                        continue
                    if text[key][-1] == "\n":
                        text[key] = text[key][:-1]
                        continue
                    break
        return text


if __name__ == "__main__":
    doc = """
!lang ja
--------
これはテストドキュメンテーションテキストだよ。
気にしないでね。

Parameters
----------
test1 : str
    テスト１。
test2 : int
    テスト２。
test3 : str, default わお
    テスト３。

Examples
--------
これが例か...
いやこれなんだよ。

Raises
------
TestError : わお
HoiHoiError : ありゃしない

!lang en
--------
This is the test documentation text.
I wanna be the guy!

Parameters
----------
test1 : str
    test1
test2 : str

!test
-----
test

Notes
-----
Finish!
"""
    dp = DocParser()
    dp.add_event(lambda line, now, before: print("お、テストじゃん！"),
                 "test")

    data = dp.parse(doc, first_indent_count=0)
    for key in data:
        print("\n-----", key, "------")
        print(data[key])
