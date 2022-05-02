# Free RT Util - Markdowns

from discord import Embed
from typing import Tuple

newlinestr = '\n'


def decoration(markdown: str, separate: int = 0) -> str:
    """見出しが使われているマークダウンをDiscordで有効なものに変換します。  
    ただたんに`# ...`を`**#** ...`に変換して渡された数だけ後ろに改行を付け足すだけです。
    Parameters
    ----------
    markdown : str
        変換するマークダウンです。
    separate : int, default 1
        見出しを`**`で囲んだ際に後ろに何個改行を含めるかです。"""
    new = ""
    for line in markdown.splitlines():
        if line.startswith(("# ", "## ", "### ", "#### ", "##### ")):
            line = f"**#** {line[line.find(' ')+1:]}"
        if line.startswith(("\n", "**#**")):
            line = f"{newlinestr * separate}{line}"
        new += f"{line}\n"
    return new


def separate(text: str, character: str = "\n") -> Tuple[str, str]:
    "指定された文字列を指定された文字の左右で分けます。"
    return text[: (i := text.find(character))], text[i + 1:]


def create_embed(markdown: str, **kwargs) -> Embed:
    """渡されたマークダウンの文字列をタイトルと説明とフィールドが設定されている`discord.Embed`に変換します。  
    見出しは三段階設定することができ、一段でタイトルで二段でフィールドそして三段で`**#** ...`のようになります。  
    もしフィールドの`inline`を`False`にしたい場合は`## !`のようにしてください。
    Parameters
    ----------
    markdown : str
        変換するマークダウンです。
    kwargs : dict
        `discord.Embed`のインスタンス作成時に渡すキーワード引数です。
    Examples
    --------
    ```
    # Title
    Description
    ## Field1
    Field1 value
    ### Field1 Child1
    Field1 Child1 Value
    #### Field1 Child2
    Field1 Child2 Value
    ## Field2
    Field2 value
    ### Field2 Child1
    Field2 Child1 Value
    #### Field2 Child2
    Field2 Child2 Value
    ```"""
    kwargs["title"], fields = separate(markdown)
    fields, kwargs["title"] = fields.split("\n## "), kwargs["title"][2:]
    kwargs["description"] = decoration(fields[0])
    del fields[0]
    embed = Embed(**kwargs)
    for field in fields:
        (name, value), inline = separate(field), True
        if name.startswith("!"):
            inline, name = False, name[1:]
        embed.add_field(
            name=name, value=decoration(value), inline=inline
        )
    return embed
