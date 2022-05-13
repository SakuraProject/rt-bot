# Free-RT.thread_manager - Constants


DB = "ThreadManager"    # データベースのテーブル名です。
MAX_CHANNELS = 10       # 設定できるチャンネル数の最大です。


# スレッド作成専用チャンネルのチャンネルプラグインのヘルプです。
HELP = {
    "ja": ("スレッド作成専用チャンネル",
           """# スレッド作成専用チャンネルプラグイン
`rt>thread`をチャンネルのトピックに入れることでそのチャンネルにメッセージを送信するとスレッドが自動でつくられるようになります。  
Botが送信したメッセージでもスレッドを作るようにするには`rt>thread bot`のようにしてください。

### 注意
この機能を使ったチャンネルで低速モードが十秒より下な場合は自動で低速モードが十秒で設定されます。  
これはスレッドの作りすぎでAPI制限になりRTがDiscordと通信できなくなるというのを防ぐためです。  
ご了承ください。"""),
    "en": ("Dedicated thread creation channel function",
           """# Dedicated thread creation channel plugin
By adding `rt>thread` to the channel topic, a thread will be created automatically when a message is sent to the channel.  
If you want to create thread by bot, you can enable this by adding `rt>thread bot`.

### Warning.
If your channel uses this feature and the slow mode is lower than 10 seconds, the slow mode will be automatically set to 10 seconds.  
The reason for this is to prevent excessive thread creation, which may limit the API and prevent RT from communicating with Discord.  
Thank you for your understanding.""")
}
