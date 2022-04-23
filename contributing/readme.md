(このフォルダは日本語での説明となります。現状英語は存在しません。  
 There aren't any English versions of contributing guide. Sorry.)
# Contributing
このフォルダでは開発に役立つような情報や開発をするときに注意すべき点などをまとめたものです。  

## ファイルマップ
いくつかの項目は長いため、ファイル別に分けています。
* [RTの全体的な仕組み](./sikumi.md)
* [Cogsについて](./about_cogs.md)
* [utilについて](./about_util.md)
* [free RTのpythonでの構文・記法](./syntax.md)

## コミットメッセージ
なるべく以下のような感じにすると嬉しいです。
```md
# 新しく何かを作った場合
new: 内容

# 更新をした場合
update: 内容

# バグ修正をした場合
fix: 内容

# 何か変更をした場合
change: 内容
```
### 注釈
コミットメッセージの最初のタグ(`fix`や`new`など)の後に`[]`を使って以下のように注釈を付け加えるとより嬉しいです。
```md
# 文字列を変えただけの場合
change[text]: 内容

# ドキュメンテーションを変えただけの場合
change[doc]: 内容
```


## RT開発の環境について
free-RTは現在nextcordで開発されています。さらにいくつかの機能を拡張して使いやすくしています。  
そのためいくつか本家discord.pyとは違う点があるので注意してください。  
free-RTではdiscord.pyに書き換えを行う計画があります。もし書き換えに協力したかったら公式サーバーかgithubのissueまで。

### commands.commandの引数
commands.commandの引数にextrasをつけることができます。
```python
{
    "headding":{"ja":"...", "en":"..."},
    "parent":"ServerPanel"
}
```
extrasの引数はこのようにheaddingとparentで構成されています。  
headdingには日本語と英語でコマンドの簡潔な説明を、parentにはRTのヘルプで出すカテゴリを英語で入れてください。

### Context.sendの多言語拡張(対応済み)
Context.sendのcontent引数に{"ja":"...", "en":"..."}の形式で辞書を入れると、
自動で言語を判別してその言語にあった内容が送信されるようになります。  
現時点で全て対応済みですが、新しくsendする場合は作ると良いでしょう。

### Cog内でのon_readyについて
Cogはon_readyが呼ばれてからロードされるので、Cog内ではon_readyの代わりとしてinit関数を使うかon_full_readyが使えます。  
on_full_readyイベントはfree-rtが全てのCogを読み込んだ後に呼ばれます。
