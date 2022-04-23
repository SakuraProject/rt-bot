# Free RTの基本データ。

from typing import Optional

from discord.ext import commands


class Colors:
    normal = 0x0066ff
    unknown = 0x80989b
    error = 0xeb6ea5
    player = 0x2ca9e1
    queue = 0x007bbb


data = {
    "prefixes": {
        "test": [
            "rf2!", "RF2!", "rf2.", "Rf2.",
            "りふちゃん２　", "りふちゃん2 ", "rf2>"
        ],
        "production": [
            "rf!", "りふ！", "RF!", "rf.", "Rf.",
            "RF.", "rF.", "りふ.", "Rf!", "rF!", "りふ!"
        ],
        "sub": [
            "rf#", "りふちゃん ", "りふたん ", "りふ ",
            "りふちゃん　", "りふたん　", "りふ　", "Rf#", "RF#", "rF#"
        ],
        "alpha": ["rf3!", "rf3>"]
    },
    "colors": {name: getattr(Colors, name) for name in dir(Colors)},
    "admins": [
        634763612535390209, 266988527915368448,
        667319675176091659, 693025129806037003,
        757106917947605034, 603948934087311360,
        875651011950297118, 608788412367110149,
        510590521811402752, 705264675138568192, 
        484655503675228171, 808300367535144980,
        809240120884330526
    ]
}


RTCHAN_COLORS = {
    "normal": 0xa6a5c4,
    "player": 0x84b9cb,
    "queue": 0xeebbcb
}


PERMISSION_TEXTS = {
    "administrator": "管理者",
    "view_audit_log": "監査ログを表示",
    "manage_guild": "サーバー管理",
    "manage_roles": "ロールの管理",
    "manage_channels": "チャンネルの管理",
    "kick_members": "メンバーをキック",
    "ban_members": "メンバーをBAN",
    "create_instant_invite": "招待を作成",
    "change_nickname": "ニックネームの変更",
    "manage_nicknames": "ニックネームの管理",
    "manage_emojis": "絵文字の管理",
    "manage_webhooks": "ウェブフックの管理",
    "manage_events": "イベントの管理",
    "manage_threads": "スレッドの管理",
    "use_slash_commands": "スラッシュコマンドの使用",
    "view_guild_insights": "チャンネルを見る",
    "send_messages": "メッセージを送信",
    "send_tts_messages": "テキスト読み上げメッセージを送信する",
    "manage_messages": "メッセージの管理",
    "embed_links": "埋め込みリンク",
    "attach_files": "ファイルを添付",
    "read_message_history": "メッセージ履歴を読む",
    "mention_everyone": "@everyone、@here、全てのロールにメンション",
    "external_emojis": "外部の絵文字を使用する",
    "add_reactions": "リアクションの追加",
    "connect": "接続",
    "speak": "発言",
    "stream": "WEB カメラ",
    "mute_members": "メンバーをミュート",
    "deafen_members": "メンバーのスピーカーをミュート",
    "move_members": "メンバーを移動",
    "use_voice_activation": "音声検出を使用",
    "priority_speaker": "優先スピーカー"
}


EMOJIS = {
    "levelup":"⤴️"
}
