# Free RT�̊�{�f�[�^�B

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
            "��ӂ����Q�@", "��ӂ����2 ", "rf2>"
        ],
        "production": [
            "rf!", "��ӁI", "RF!", "rf.", "Rf.",
            "RF.", "rF.", "���.", "Rf!", "rF!", "���!"
        ],
        "sub": [
            "rf#", "��ӂ���� ", "��ӂ��� ", "��� ",
            "��ӂ����@", "��ӂ���@", "��Ӂ@", "Rf#", "RF#", "rF#"
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
    "administrator": "�Ǘ���",
    "view_audit_log": "�č����O��\��",
    "manage_guild": "�T�[�o�[�Ǘ�",
    "manage_roles": "���[���̊Ǘ�",
    "manage_channels": "�`�����l���̊Ǘ�",
    "kick_members": "�����o�[���L�b�N",
    "ban_members": "�����o�[��BAN",
    "create_instant_invite": "���҂��쐬",
    "change_nickname": "�j�b�N�l�[���̕ύX",
    "manage_nicknames": "�j�b�N�l�[���̊Ǘ�",
    "manage_emojis": "�G�����̊Ǘ�",
    "manage_webhooks": "�E�F�u�t�b�N�̊Ǘ�",
    "manage_events": "�C�x���g�̊Ǘ�",
    "manage_threads": "�X���b�h�̊Ǘ�",
    "use_slash_commands": "�X���b�V���R�}���h�̎g�p",
    "view_guild_insights": "�`�����l��������",
    "send_messages": "���b�Z�[�W�𑗐M",
    "send_tts_messages": "�e�L�X�g�ǂݏグ���b�Z�[�W�𑗐M����",
    "manage_messages": "���b�Z�[�W�̊Ǘ�",
    "embed_links": "���ߍ��݃����N",
    "attach_files": "�t�@�C����Y�t",
    "read_message_history": "���b�Z�[�W������ǂ�",
    "mention_everyone": "@everyone�A@here�A�S�Ẵ��[���Ƀ����V����",
    "external_emojis": "�O���̊G�������g�p����",
    "add_reactions": "���A�N�V�����̒ǉ�",
    "connect": "�ڑ�",
    "speak": "����",
    "stream": "WEB �J����",
    "mute_members": "�����o�[���~���[�g",
    "deafen_members": "�����o�[�̃X�s�[�J�[���~���[�g",
    "move_members": "�����o�[���ړ�",
    "use_voice_activation": "�������o���g�p",
    "priority_speaker": "�D��X�s�[�J�["
}


EMOJIS = {
    "levelup":"??"
}