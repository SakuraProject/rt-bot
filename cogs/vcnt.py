from discord.gateway import DiscordVoiceWebSocket
from discord import VoiceClient, Embed, File, Message
from discord.ext import commands
import aiohttp
import urllib.parse
import discord
import json
import struct
import nacl.secret
import time
from collections import defaultdict
from discord.opus import Decoder as DiscordDecoder
from discord.opus import exported_functions, OpusError, c_float_ptr
import sys
import ctypes
import os
import logging
from itertools import zip_longest
import numpy as np
from discord.utils import get
import asyncio
import threading
import subprocess
import wave
import array
from util import RTCPacket, PacketQueue, BufferDecoder, Decoder
import pyopenjtalk
from discord.ext.commands import Context
from typing import Union, Optional, Sequence, Any
from discord.sticker import GuildSticker, StickerItem
from discord.mentions import AllowedMentions
from discord.message import MessageReference, PartialMessage
from discord.ui import View

#imports of Uses StrToCommand
from cogs.music.music import Music, is_url
from youtube_dl import YoutubeDL
from cogs.music.player import Player
import re
class StrToCommand:
    def __init__(self, bot, ctx, vc):
        self.bot = bot
        self.ctx = ctx
    async def convert(self, tex):
        afk = ["afk(の|を)(.+)(で登録して|でセットして)","(.+)(でafkの登録して|でafkをセットして)"]
        rais = ["ライズして","掲示板の(表示順位|順位)を(あげて|上げて)"]
        play = ["(.+)を(再生して|流して)"]
        repeate = ["(曲|音楽)を(繰り返して|ループして)"]
        slowmode = ["(低速を|ていそくを)(.+)秒(にして|に設定して|にセットして)"]
        prf = self.bot.command_prefix[0]
        #afk check
        rem = await self.regmatch(tex, afk)
        if rem:
            cmd = re.sub("afk(の|を)","",tex)
            cmd = re.sub("(で登録して|でセットして)","",cmd)
            cmd = re.sub("(でafkの登録して|でafkをセットして)","",cmd)
            cmd = prf + "afk set " + cmd
            return cmd
        #raise check
        rem = await self.regmatch(tex, rais)
        if rem:
            cmd = prf + "raise"
            return cmd
        #play check
        rem = await self.regmatch(tex, play)
        if rem:
            cmd = re.sub("を(再生して|流して)","",tex)
            ydlo = {'format': 'bestaudio','noplaylist': 'True'}
            with YoutubeDL(ydlo) as ydl:
                id=ydl.extract_info('ytsearch:'+cmd,download=False)['entries'][0]['id']
                cmd = 'https://youtube.com/watch?v='+id
            cmd = prf + "play " + cmd
            self.bot.cogs["Music"].now = Player(self.bot.cogs["Music"], self.ctx.guild, self.vc)
            return cmd
        rem = await self.regmatch(tex, repeate)
        if rem:
            cmd = prf + "repeate auto"
            return cmd
        rem = await self.regmatch(tex, slowmode)
        if rem:
            cmd = re.sub("(低速を|ていそくを)","",tex)
            cmd = re.sub("秒(にして|に設定して|にセットして)","",cmd)
            cmd = prf + "slowmode " + cmd
            return cmd
        return tex

    async def regmatch(self, tex, rar):
        for rg in rar:
            mch = re.match(rg, tex)
            if mch:
                return [rg,mch]
        return None

class TtsContext(Context):
    OPENJTALK = "open_jtalk"
    "なんのコマンドでOpenJTalkを実行するかです。"
    OPENJTALK_DICTIONARY = "cogs/tts/lib/OpenJTalk/dic"
    "OpenJTalkで使う辞書がある場所です。"
    OPENJTALK_VOICE_DIRECTORY = "cogs/tts/lib/OpenJTalk"
    "OpenJTalkで使う音声のデータがあるディレクトリです。"
    OPENJTALK_VOICE_NAME = "mei.htsvoice"
    async def reply(self, content: Optional[str] = None, **kwargs: Any) -> Message:
        await self.send(content, **kwargs)

    async def send(
        self,
        content: Optional[str] = None,
        *,
        tts: bool = False,
        embed: Optional[Embed] = None,
        embeds: Optional[Sequence[Embed]] = None,
        file: Optional[File] = None,
        files: Optional[Sequence[File]] = None,
        stickers: Optional[Sequence[Union[GuildSticker, StickerItem]]] = None,
        delete_after: Optional[float] = None,
        nonce: Optional[Union[str, int]] = None,
        allowed_mentions: Optional[AllowedMentions] = None,
        reference: Optional[Union[Message, MessageReference, PartialMessage]] = None,
        mention_author: Optional[bool] = None,
        view: Optional[View] = None,
        suppress_embeds: bool = False,
        ephemeral: bool = False,
    ) -> Message:
        swav = str(self.guild.id)+'-vcnt.wav'
        sc = ""
        if not content is None:
            sc = content
        if not embed is None:
            sc = sc + embed.description
        if not embeds is None:
            for e in embeds:
                sc = sc + e.description
        args = [self.OPENJTALK,"-x",self.OPENJTALK_DICTIONARY,"-m",self.OPENJTALK_VOICE_DIRECTORY+"/"+self.OPENJTALK_VOICE_NAME,'-r','1.0','-ow',swav]
        p = subprocess.run(args,input=sc.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        channel = self.message.author.voice.channel
        voice = get(self.bot.voice_clients, guild=self.guild)
        if voice and voice.is_connected():
            pass
        else:
            voice = await channel.connect()
        voice.play(discord.FFmpegPCMAudio(swav))
        await asyncio.sleep(1000)
        os.remove(swav)

class NewVoiceWebSocket(DiscordVoiceWebSocket):
    cli = None
    IDENTIFY = 0
    SELECT_PROTOCOL = 1
    READY = 2
    HEARTBEAT = 3
    SESSION_DESCRIPTION = 4
    SPEAKING = 5
    HEARTBEAT_ACK = 6
    RESUME = 7
    HELLO = 8
    RESUMED = 9
    CLIENT_CONNECT = 12
    CLIENT_DISCONNECT = 13
    ssrc_map = dict()

    async def received_message(self, msg):
        await super(NewVoiceWebSocket, self).received_message(msg)
        op = msg["op"]
        data = msg.get("d")
        if op == self.READY:
            await self.initial_connection(data)
        elif op == self.HEARTBEAT_ACK:
            self._keep_alive.ack()
        elif op == self.RESUMED:
            pass
        elif op == self.SESSION_DESCRIPTION:
            self.cli.mode = data["mode"]
            self.cli.secret_key = data["secret_key"]
            self._connection.mode = data["mode"]
            self._connection.secret_key = data["secret_key"]
            await self.load_secret_key(data)
        elif op == self.HELLO:
            pass

        elif op == self.SPEAKING:
            ssrc = data["ssrc"]
            user = int(data["user_id"])
            speaking = data["speaking"]
            if ssrc in self.ssrc_map:
                self.ssrc_map[ssrc]["speaking"] = speaking
            else:
                self.ssrc_map.update({ssrc: {"user_id": user, "speaking": speaking}})
            await self.cli.record_by_ssrc(ssrc)

class NewVoiceClient(VoiceClient):
    ctx=None
    bot = None
    def __init__(self, client, channel):
        super().__init__(client, channel)
        self.record_task = dict()
        self.decoder = dict()
        self.record_task_ssrc = dict()
        self.loops = dict()
        self.is_recording = dict()
        self.is_talking = dict()
        self.is_talking1 = dict()
        self.conected = True

    def disco(self):
        for task in self.record_task:
            task.cancel()
        self.conected = False
        self.record_task = dict()
        self.decoder = dict()
        self.record_task_ssrc = dict()
        self.loops = dict()
        self.is_recording = dict()
        self.is_talking = dict()
        self.is_talking1 = dict()

    async def recv_voice_packet(self, ssrc):
        asyncio.ensure_future(self.check_talk(ssrc))
        self.is_talking1[ssrc] = False
        while True:
            if not self.is_recording[ssrc] and self.is_talking1[ssrc]:
                self.is_talking1[ssrc] = False
                _basedir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                julius      = "julius"
                main        = os.path.join(_basedir, "julius-dict", "main.jconf")
                am_dnn      = os.path.join(_basedir, "julius-dict", "am-dnn.jconf")
                julius_dnn  = os.path.join(_basedir, "julius-dict", "julius.dnnconf")
                input_audio_filefm = await self.decoder[ssrc].decode(ssrc)
                input_audio_file  = "ffmpeg"+str(input_audio_filefm)
                argsfm = ["ffmpeg", "-y", "-i", input_audio_filefm, "-ac", "1", "-ar", "16000", input_audio_file]
                pfm = subprocess.run(argsfm, stdout=subprocess.PIPE, text=True, encoding="utf-8")
                #print(pfm.stdout)
                args = [julius, "-C", main, "-C", am_dnn, "-dnnconf", julius_dnn, "-input", "rawfile", "-cutsilence"]
                p = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,stdin=asyncio.subprocess.PIPE)
                stdout, stderr = await p.communicate(input=input_audio_file.encode())
                #print(p.stdout)
                try:
                    output = stdout.decode().split("### read waveform input")[1].split("\n\n")
                except IndexError:
                    output = list()
                for i in output:
                    try:
                        sentence = i.split("sentence1:")[1].split("\n")[0].replace(" ", "")
                    except IndexError:
                        continue
                    print(sentence)
                    if not sentence.startswith("りふ"):
                        continue
                    cmd = sentence.translate(str.maketrans({chr(0xFF01 + i): chr(0x21 + i) for i in range(94)}))[2:]
                    ctxte = self.ctx
                    userid = self.ws.ssrc_map[ssrc]["user_id"]
                    author = msg.guild.get_member(userid)
                    ctxte.author = author
                    stc = StrToCommand(self.bot,ctxte,self)
                    cmd = stc.convert(cmd)
                    msg=self.ctx.message
                    #print(msg.author.name)
                    msg.author = author
                    msg.content = cmd
                    tctx = await self.bot.get_context(msg,cls=TtsContext)
                    if tctx.valid:
                        os.remove(input_audio_filefm)
                        os.remove(input_audio_file)
                        await self.bot.invoke(tctx)
                    else:
                        try:
                            os.mkdir('vcnterrors')
                        except FileExistsError as e:
                            pass
                        os.rename(input_audio_filefm,'vcnterrors/'+input_audio_filefm)
                        os.rename(input_audio_file,'vcnterrors/'+input_audio_file)
                        with open('vcnterrors/'+input_audio_file+'.txt', 'w') as f:
                            print(sentence, file=f)
            recv = await self.loop.sock_recv(self.socket, 2 ** 16)
            if 200 <= recv[1] < 205:
                continue
            decrypt_func = getattr(self, f'decrypt_{self.mode}')
            header, data = decrypt_func(recv)
            packet = RTCPacket(header, data)
            packet.set_real_time()
            packet.calc_extension_header_length()
            if len(packet.decrypted) < 10 and not self.is_recording[ssrc]:
                pass
            elif not len(packet.decrypted) < 10:
                self.decoder[ssrc].recv_packet(packet)
                self.is_recording[packet.ssrc] = True
                self.is_talking[packet.ssrc] = True
                self.is_talking1[packet.ssrc] = True

    async def check_talk(self, ssrc):
        while True:
            try:
                if self.is_talking[ssrc]:
                    self.is_talking[ssrc] = False
                else:
                    self.is_recording[ssrc] = False
            except KeyError:
                self.is_talking[ssrc] = False
            await asyncio.sleep(3)
            if not self.conected:
                break

    async def connect_websocket(self) -> NewVoiceWebSocket:
        ws = await NewVoiceWebSocket.from_client(self)
        ws.cli = self
        self._connected.clear()
        while ws.secret_key is None:
            await ws.poll_event()
        self._connected.set()
        return ws


    async def record_by_ssrc(self, ssrc):
        # init
        self.is_recording[ssrc] = True
        self.decoder[ssrc] = BufferDecoder(self)

        # do record
        self.record_task[ssrc] = self.loop.create_task(self.recv_voice_packet(ssrc))


    async def record_stop_by_ssrc(self, ssrc):
        self.record_task[ssrc].cancel()
        # clear data
        self.record_task[ssrc] = None
        self.is_recording[ssrc] = False
        return self.decoder[ssrc].decode(ssrc)

    def decrypt_xsalsa20_poly1305(self, data: bytes) -> tuple:
        box = nacl.secret.SecretBox(bytes(self.secret_key))
        is_rtcp = 200 <= data[1] < 205
        if is_rtcp:
            header, encrypted = data[:8], data[8:]
            nonce = bytearray(24)
            nonce[:8] = header
        else:
            header, encrypted = data[:12], data[12:]
            nonce = bytearray(24)
            nonce[:12] = header
        return header, box.decrypt(bytes(encrypted), bytes(nonce))

    def decrypt_xsalsa20_poly1305_suffix(self, data: bytes) -> tuple:
        box = nacl.secret.SecretBox(bytes(self.secret_key))
        is_rtcp = 200 <= data[1] < 205
        if is_rtcp:
            header, encrypted, nonce = data[:8], data[8:-24], data[-24:]
        else:
            header, encrypted, nonce = data[:12], data[12:-24], data[-24:]
        return header, box.decrypt(bytes(encrypted), bytes(nonce))

    def decrypt_xsalsa20_poly1305_lite(self, data: bytes) -> tuple:
        box = nacl.secret.SecretBox(bytes(self.secret_key))
        is_rtcp = 200 <= data[1] < 205
        if is_rtcp:
            header, encrypted, _nonce = data[:8], data[8:-4], data[-4:]
        else:
            header, encrypted, _nonce = data[:12], data[12:-4], data[-4:]
        nonce = bytearray(24)
        nonce[:4] = _nonce
        return header, box.decrypt(bytes(encrypted), bytes(nonce))



class vcnt(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self._closing = dict()
        self.ctxs = dict()
    @commands.group(name="voicecnt")
    async def voicecnt(self, ctx):
        channel = ctx.message.author.voice.channel
        voice = get(self.bot.voice_clients, guild=ctx.guild)
        if voice and voice.is_connected():
            await voice.move_to(channel)
        else:
            voice = await channel.connect(cls=NewVoiceClient)
        voice.ctx = ctx
        voice.bot = self.bot
        self._closing[ctx.guild.id] = False
        self.ctxs[ctx.guild.id] = ctx

    @voicecnt.command()
    async def disconnect(self, ctx):
        voice = get(self.bot.voice_clients, guild=ctx.guild)
        await voice.disconnect()
        self._closing[ctx.guild.id] = True
        await self.ctxs[ctx.guild.id].send("切断しました")

    @commands.Cog.listener()
    async def on_voice_abandoned(self, voice_client: discord.VoiceClient):
        # 放置された場合は切断する。
        if voice_client.guild.id in self._closing and not self._closing[member.guild.id]:
            await self.ctxs[voice_client.guild.id].send("一人ぼっちになったので切断しました。")
            voice_client.disco()
            await voice_client.disconnect()
            self._closing[voice_client.guild.id] = True

    @commands.Cog.listener()
    async def on_voice_leave(self, member: discord.Member, _, __):
        if member.id == self.bot.user.id and member.guild.id in self._closing \
                and not self._closing[member.guild.id]:
            await self.ctxs[member.guild.id].send("ｷｬｯ、誰かにVCから蹴られたかバグが発生しました。")
            self._closing[member.guild.id] = True

def setup(bot):
    return bot.add_cog(vcnt(bot))