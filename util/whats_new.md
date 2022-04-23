# What's new
util統合による更新ログみたいなものです。

## 機能移動
utilへの統合により以下の関数の名前が変更になりました。

### rtutil
* rtutil.check_int -> util.isintable
* rtutil.similer -> util.olds.similer
* rtutil.has_roles -> util.has_any_roles
* rtutil.role2obj -> util.olds.role2obj
* rtutil.get_webhook -> util.get_webhook
* rtutil.clean_content -> util.olds.clean_content
* rtutil.converters.xxx
    -> それぞれのコンバータが独立。  
    Members -> util.MembersConverter  
    TextChannels -> util.TextChannelsConverter  
    VoiceChannels -> util.VoiceChannelsConverter  
    Roles -> util.RolesConverter
* rtutil.markord -> util.markdowns
* rtutil.Minesweeper -> util.MineSweeper (内容が変更、詳細はminesweeper.py)
* rtutil.securl -> 変更なし
* rtutil.views.TimeoutView -> util.TimeoutView

### rtlib
ほとんどそのまま移行してます。
* rtlib.cacher -> util.cacher
* rtlib.page -> util.page
* rtlib.rtws -> util.rtws
* rtlib.slash -> util.slash
* rtlib.websocket -> util.websocket
* rtlib.typed -> util.bot, util.typesの2つに分割
* rtlib.ext -> いくつかの項目はutil.ext、残りはutilに直接移動
* rtlib.mysql_manager -> util.mysql_manager
* rtlib.Table (rtlib.data_manager.Table) -> util.Table (util.lib_data_manager.Table)

## 機能追加
utilへの統合でいくつかの機能が追加されました。
* util.has_all_roles