# RTの読み上げ
RTの読み上げではOpenJTalkとAquesTalkとgTTSを使用します。

## Installation
### OpenJTalk
1. `open_jtalk`からOpenJTalkを実行できるようにする。
2. `cogs/tts/lib`に`OpenJTalk`というフォルダを作る。
3. `cogs/tts/lib/OpenJTalk`に`dic`というフォルダを作りそこにOpenJTalkの辞書を入れる。
4. `cogs/tts/lib/OpenJTalk`に`cogs/tts/data/avaliable_voices.json`にあるOpenJTalkのボイスに対応する`htsvoice`を`<openjtalk.KeyName>.htsvoice`のように配置する。
   (もちろん使用するものだけでOKです。)

※ 1の実行コマンドは`cogs/tts/agents.py`の`OPENJTALK`の定数から変更が可能で、絶対パスを指定することが可能です。  
※ 2の辞書のパスは`cogs/tts/agents.py`の`OPENJTALK_DICTIONARY`の定数を変更することによって別の場所に配置することが可能です。
### AquesTalk
まずAquesTalkのライブラリをダウンロードして、そこにあるゆっくり霊夢である`f1`とゆっくり魔理沙である`f2`を使用して`cogs/tts/lib/AquesTalk/aquestalk.c`をコンパイルしてください。  
そして完成した`f1`と`f2`の実行ファイルを`AquesTalk`に配置してください。
#### Notes
Pythonには`ctypes`というもので`dll`,`dylib`,`so`を実行することができます。  
RTでそれを使用していない理由は`Segmentation fault`のトラウマがあるからです。  
ですので`ctypes`使えばなど何も言わないでください。
### gTTS
`requirements.txt`にあるものをインストールしていれば特に何もする必要はありません。