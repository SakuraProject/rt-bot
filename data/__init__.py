# Free RTの基本データ。

from inspect import cleandoc


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
            "RF.", "rF.", "りふ.", "Rf!", "rF!", "りふ!",
            "rf>", "Rf>", "rF>"
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
        809240120884330526, 739702692393517076
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
    "use_application_commands": "スラッシュコマンドの使用",
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
    "levelup": "⤴️",
    # ここよりしたの行にある絵文字は置き換えが必要。
    # (置き換えをした場合はこれらのコメントの上に持ってきてください。)
    "UserFlags": {
        "hypesquad_bravery": "<:HypeSquad_Bravery:876337861572579350>",
        "hypesquad_brilliance": "<:HypeSquad_Brilliance:876337861643882506>",
        "hypesquad_balance": "<:HypeSquad_Balance:876337714679676968>",
    },
    "yahoo_search": "<:search:876360747440017439>"
}


# bot_generalで使うものたち。

ERROR_CHANNEL = 962977145716625439

INFO_DESC = {
    "ja": """どうもFree RTという新時代Botです。
このBotは役職,投票,募集,チケットパネルやチャンネルステータスなどの定番機能はもちろん、声の変えれる読み上げやプレイリストのある音楽プレイヤーなどもある多機能Botです。
そして荒らし対策として使える画像,ウェブ,合言葉認証やスパム対策機能まであります。
またその他にもスレッド自動アーカイブ対策,自己紹介テンプレートに使える常に下にくるメッセージ,NSFW誤爆対策に使える自動画像スポイラーそしてボイスチャンネルロールなどあったら便利な機能もたくさんあります。
さあ是非このBotを入れて他のBotを蹴り飛ばしましょう！""",
    "en": """It's a new era Bot called Free RT.
This Bot is a multifunctional Bot with standard functions such as job title, voting, recruitment, ticket panel and channel status, as well as a music player with voice changing reading and playlists.
And there are images, web, password authentication and spam prevention functions that can be used as a troll countermeasure.
Other useful features include automatic thread archiving, always-on messages for self-introduction templates, an automatic image spoiler for NSFW detonation, and voice channel rolls.
Come on, let's put this Bot in and kick the other Bots."""
}
INFO_ITEMS = (("INVITE", {"ja": "招待リンク", "en": "invite link"}),
              ("SS", {"ja": "サポートサーバー", "en": "support server"}),
              ("URL", {"ja": "RTのウェブサイト", "en": "free-RT offical website"}),
              ("GITHUB", {"ja": "GitHub", "en": "GitHub"}),
              ("CREDIT", {"ja": "クレジット", "en": "Credit"}))
INFO_INVITE = "https://discord.com/api/oauth2/authorize?client_id=961521106227974174&permissions=8&scope=bot%20applications.commands"
INFO_SS, INFO_URL = "https://discord.gg/KW4CZvYMJg", "https://free-rt.com"
INFO_GITHUB = """* [free-RT-developers](https://github.com/free-RT)
* [RT-Bot](https://github.com/free-RT/rt-bot)
* [RT-Backend](https://github.com/free-RT/rt-backend)
* [RT-Frontend](https://github.com/free-RT/rt-frontend)"""
INFO_CREDIT = "[ここをご覧ください。](https://free-rt.com/credit.html)"

THANKYOU_TEMPLATE = cleandoc(
    """free-RTの導入ありがとうございます。
    よろしくお願いします。
    もし何かバグや要望があればウェブサイトから公式サポートサーバーにてお伝えください。

    **RT 情報**
    公式ウェブサイト：https://free-rt.com
    サポートサーバー：https://discord.gg/KW4CZvYMJg
    チュートリアル　：https://rt-team.github.io/ja/notes/tutorial
    プリフィックス　：`rf!`, `りふ！`, `RF!`, `rf.`, `Rf.`, `RF.`, `rF.`, `りふ.`, `Rf!`, `rF!`, `りふ!`

    **free-RT 利用規約**
    RTを利用した場合以下の利用規約に同意したことになります。
    https://free-rt.com/terms.html

    **free-RT プライバシーポリシー**
    RTのプライバシーポリシーは以下から閲覧可能です。
    https:/free-rt.com/privacy.html

    **If you do not understand Japanese**
    You can check what is written above in English by pressing the button at the bottom."""
)


# helpのカテゴリー
HELP_CATEGORIES = {
    "bot": "RT",
    "server-tool": "ServerTool",
    "server-panel": "ServerPanel",
    "server-safety": "ServerSafety",
    "server-useful": "ServerUseful",
    "entertainment": "Entertainment",
    "individual": "Individual",
    "chplugin": "ChannelPlugin",
    "music": "Music",
    "other": "Other"
}
HELP_CATEGORIES_JA = {
    "ServerTool": "サーバーツール",
    "ServerPanel": "サーバーパネル",
    "ServerSafety": "サーバー安全",
    "ServerUseful": "サーバー便利",
    "Entertainment": "娯楽",
    "Individual": "個人",
    "ChannelPlugin": "チャンネルプラグイン",
    "Music": "音楽",
    "Other": "その他"
}


# rtfmで使うもの。

RTFM_URL = {
    "latest": "https://discordpy.readthedocs.io/en/latest/",
    "stable": "https://discordpy.readthedocs.io/en/stable/",
    "v1.7.3": "https://discordpy.readthedocs.io/en/v1.7.3/",
    "v1.7.2": "https://discordpy.readthedocs.io/en/v1.7.2/",
    "v1.7.1": "https://discordpy.readthedocs.io/en/v1.7.1/",
    "v1.7.0": "https://discordpy.readthedocs.io/en/v1.7.0",
    "v1.6.0": "https://discordpy.readthedocs.io/en/v1.6.0",
    "legacy": "https://discordpy.readthedocs.io/en/legacy/",
    "async": "https://discordpy.readthedocs.io/en/async/",
    "ja_latest": "https://discordpy.readthedocs.io/ja/latest/",
    "ja_stable": "https://discordpy.readthedocs.io/ja/stable/",
}
