# utilについて
旧rtutilと旧rtlibは共にRTに関するお役立ちツールが集まったものになっていました。  
この2つは統合し、utilというフォルダで作業されています。  
これらの機能は

## utilにあるもの
* webhook_send (`channel.webhook_send`を使える機能)
* componesy (`discord.ui.View`を簡単に作るためのもの)
* mysql_manager (DBマネージャー)
* lib_data_manager (DBマネージャー②)
* discord.ext.tasksのタスクがデータベースの操作失敗によって止まることがないようにする機能 (標準搭載)
* sendKwargs (ctx.sendにはあるけどinteractionresponce.send_messageにはないKwargsを削除して返す関数っぽい)
* RT (AutoShardedBotを継承したサブクラス、起動時に使っている)
* @websocketデコレータ (ws通信を簡単に行う機能らしい)
* WebSocketManager (ws関連のCog)
* rtws (さっきのwebsocketとは分離されている、RT専用のws機能)
* EmbedPage (buttonを使ってページのようなことを簡単にできるようにしたもの)
* Slash関連 (スラッシュコマンドを通常のcommands.commandと互換性を持たせた状態にするための機能)
* Cacher (キャッシュ管理)
* debug (デバッグ関連のCog)
* dochelp (自動ドキュメンテーションヘルプ管理)
* on_cog_addイベント (cogの追加イベント)
* on_full_reaction_add/removeイベント (rawイベントでは通常取得できないメンバーやメッセージ情報を補ったイベント)
* on_send、on_editイベント (自分がしゃべった・編集したときに発火するイベント)
* MultipleConverters (`, `によって区切っていくつかの対象を同時に取得できるコンバーター)
* data_manager (DBマネージャー③)
* markord (マークダウン変換機)
* minesweeper (マインスイーパー)
* securlAPIを叩く機能
* その他

# discord.pyへの移行に伴い変更が必要な機能について
discord.pyと現状のnextcordの変更点が多すぎるため、把握しきれていません。  
ただ「ここは改変が必要だろうな」と予想されているところを列挙しておきます。
