# free RT python記法ルール
free RTではRTの構文・記法を引き継いでいます。異論などがあれば公式サーバーまで。 

## 基本的な書き方
PEP8で文字数は90文字より少ない文字数にして欲しいです。  
ファイルの最初には以下のように`# Free-RT - ファイルにあるものの名前`のようにつけて改行をして欲しいです。
```python
# Free-RT - Help Command

...
```
  
## インポート
`impprt`は以下のようにtyping関連、discord、通常モジュール、util、同階層の順にブロック分けして欲しいです。  
それぞれのブロックの中では文字数が多い順に並べ替えをしてくれると嬉しいです。  
`if TYPE_CHECKING: ...`は一番下でお願いします。(この中でブロック分けは不要です。)
```python
from typing import TYPE_CHECKING

from discord.ext import commands
import discord

from reprypt import decrypt
from ujson import loads

from util import isintable

from .constants import DEFAULT

if TYPE_CHECKING:
    from util import RT
```
  
## インデントがない場所のものは二行ずつ
クラスや関数などでインデントがない場所にあるものは以下のように二行ずつ開けて欲しいです。
```python
def test(...) -> ...:
    ...


class Wow:
    def huga(self, ...) -> ...:
        ...

    def test(self, ...) -> ...:
        ...


def setup(bot):
    ...
```
  
## ドキュメンテーション/アノテーション
色々な場所で使われるような関数には軽いドキュメンテーションとアノテーションをつけて欲しいです。  
utilにあるものには特につけておくべきです。  
内部的に使われるものには`_`を最初につけて関数のちょっとした説明を`#`のコメントで示して欲しいです。  
`_`を先頭に付けた関数のアノテーションは不要です。  
また、discordの基本的な機能(コマンドのctx引数やsetup関数など)のアノテーションも不要です。
```python
from typing import Optional


def encode(text: str) -> Optional[str]:
    "これは渡された文字列をエンコードする関数です。"
    ...


def _plus(text):
    # これは渡されたエンコードされた文字列を拡張するものです。
    ...
```
  
外部的に使われるような変数には型アノテーションをなるべくつけるようにしてください。  
もし汚くなるようでしたらクラス直下にアノテーションをつけた変数を列挙しましょう。  
