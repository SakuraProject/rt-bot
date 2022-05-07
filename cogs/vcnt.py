from discord.gateway import DiscordVoiceWebSocket
from discord import VoiceClient
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

c_int_ptr = ctypes.POINTER(ctypes.c_int)
c_int16_ptr = ctypes.POINTER(ctypes.c_int16)
c_float_ptr = ctypes.POINTER(ctypes.c_float)

def libopus_loader(name):
    # create the library...
    lib = ctypes.cdll.LoadLibrary(name)

    # register the functions...
    for item in exported_functions:
        func = getattr(lib, item[0])

        try:
            if item[1]:
                func.argtypes = item[1]

            func.restype = item[2]
        except KeyError:
            pass

        try:
            if item[3]:
                func.errcheck = item[3]
        except KeyError:
            log.exception("Error assigning check function to %s", func)

    return lib


def _load_default():
    global _lib
    try:
        if sys.platform == 'win32':
            _basedir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            _bitness = struct.calcsize('P') * 8
            _target = 'x64' if _bitness > 32 else 'x86'
            _filename = os.path.join(_basedir, 'bin', 'libopus-0.{}.dll'.format(_target))
            _lib = libopus_loader(_filename)
        else:
            _lib = libopus_loader(ctypes.util.find_library('opus'))
    except Exception:
        _lib = None

    return _lib is not None

_load_default()

def is_loaded():
    global _lib
    return _lib is not None

MAX_SRC = 65535
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
            await cli.record_stop_by_ssrc(data['ssrc'])
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

class RTCPacket:
    def __init__(self, header, decrypted):
        self.version = (header[0] & 0b11000000) >> 6
        self.padding = (header[0] & 0b00100000) >> 5
        self.extend = (header[0] & 0b00010000) >> 4
        self.cc = header[0] & 0b00001111
        self.marker = header[1] >> 7
        self.payload_type = header[1] & 0b01111111
        self.offset = 0
        self.ext_length = None
        self.ext_header = None
        self.csrcs = None
        self.profile = None
        self.real_time = None

        self.header = header
        self.decrypted = decrypted
        self.seq, self.timestamp, self.ssrc = struct.unpack_from('>HII', header, 2)

    def set_real_time(self):
        self.real_time = time.time()

    def calc_extension_header_length(self) -> None:
        if not (self.decrypted[0] == 0xbe and self.decrypted[1] == 0xde and len(self.decrypted) > 4):
            return
        self.ext_length = int.from_bytes(self.decrypted[2:4], "big")
        offset = 4
        for i in range(self.ext_length):
            byte_ = self.decrypted[offset]
            offset += 1
            if byte_ == 0:
                continue
            offset += 1 + (0b1111 & (byte_ >> 4))

        # Discordの仕様
        if self.decrypted[offset + 1] in [0, 2]:
            offset += 1
        self.decrypted = self.decrypted[offset + 1:]

class PacketQueue:
    def __init__(self):
        self.queues = defaultdict(list)

    def push(self, packet):
        self.queues[packet.ssrc].append(packet)

    def get_all_ssrc(self):
        return self.queues.keys()

    async def get_packets(self, ssrc: int):
        last_seq = None
        packets = self.queues[ssrc]
        while len(packets) != 0:
            if last_seq is None:
                packet = packets.pop(0)
                last_seq = packet.seq
                yield packet
                continue

            if last_seq == MAX_SRC:
                last_seq = -1

            if packets[0].seq - 1 == last_seq:
                packet = packets.pop(0)
                last_seq = packet.seq
                yield packet
                continue

            # 順番がおかしかったときの場合
            for i in range(1, min(1000, len(packets))):
                if packets[i].seq - 1 == last_seq:
                    packet = packets.pop(0)
                    last_seq = packet.seq
                    yield packet
                    break
            else:
                #  該当するパケットがなかった場合、破損していたとみなす
                yield None

        # 終了
        yield -1


class BufferDecoder:
    def __init__(self, client):
        self.queue = PacketQueue()
        self.timestamp: int = 0
        self.user_timestamps = {}
        self.client = client
    def recv_packet(self, packet):
        self.queue.push(packet)

    async def _decode(self, ssrc):
        decoder = Decoder()
        pcm = []
        start_time = None

        last_timestamp = None
        async for packet in self.queue.get_packets(ssrc):
            if packet == -1:
                # 終了
                break


            if start_time is None:
                start_time = packet.real_time
            else:
                start_time = min(packet.real_time, start_time)

            if len(packet.decrypted) < 10:
                # パケットがdiscordから送られてくる無音のデータだった場合: https://discord.com/developers/docs/topics/voice-connections#voice-data-interpolation
                last_timestamp = packet.timestamp
                continue

            if last_timestamp is not None:
                elapsed = (packet.timestamp - last_timestamp) / Decoder.SAMPLING_RATE
                if elapsed > 0.02:
                    # 無音期間
                    margin = [0] * 2 * int(Decoder.SAMPLE_SIZE * (elapsed - 0.02) * Decoder.SAMPLING_RATE)
                    pcm += margin

            data = await decoder.decode_float(packet.decrypted)
            pcm += data
            last_timestamp = packet.timestamp

        del decoder

        return dict(data=pcm, start_time=start_time)

    async def decode(self, ssrc):
        file = str(ssrc)+"-"+str(time.time())+".wav"
        wav = wave.open(file, "wb")
        wav.setnchannels(Decoder.CHANNELS)
        wav.setsampwidth(Decoder.SAMPLE_SIZE // Decoder.CHANNELS)
        wav.setframerate(Decoder.SAMPLING_RATE)
        decoder = Decoder()
        for packet in self.queue.queues[ssrc]:
            if packet is None:
                # パケット破損の場合
                continue
            else:
                decoded_data = decoder.decode(packet.decrypted)
            if packet.ssrc not in self.user_timestamps:
                self.user_timestamps.update({packet.ssrc: packet.timestamp})
                # Add silence when they were not being recorded.
                silence = 0
            else:
                silence = packet.timestamp - self.user_timestamps[packet.ssrc] - 960
                self.user_timestamps[packet.ssrc] = packet.timestamp
            decoded_data = struct.pack("<h", 0) * silence * decoder.CHANNELS + decoded_data
            wav.writeframes(decoded_data)
            del decoded_data
        wav.close()
        #file.seek(0)
        self.queue.queues[ssrc] = list()
        return file

class Decoder(DiscordDecoder):
    @staticmethod
    def packet_get_nb_channels(data: bytes) -> int:
        return 2

    async def decode_float(self, data, *, fec=False):
        if not is_loaded():
            _load_default()
        if data is None and fec:
            raise OpusError("Invalid arguments: FEC cannot be used with null data")

        if data is None:
            frame_size = self._get_last_packet_duration() or self.SAMPLES_PER_FRAME
            channel_count = self.CHANNELS
        else:
            frames = self.packet_get_nb_frames(data)
            channel_count = self.packet_get_nb_channels(data)
            samples_per_frame = self.packet_get_samples_per_frame(data)
            frame_size = frames * samples_per_frame

        pcm = (ctypes.c_float * (frame_size * channel_count))()
        pcm_ptr = ctypes.cast(pcm, c_float_ptr)
        ret = _lib.opus_decode_float(self._state, data, len(data) if data else 0, pcm_ptr, frame_size, fec)

        return array.array('f',pcm[:ret * channel_count]).tobytes()

    def decode(self, data, *, fec=False):
        if data is None and fec:
            raise OpusError("Invalid arguments: FEC cannot be used with null data")

        if data is None:
            frame_size = self._get_last_packet_duration() or self.SAMPLES_PER_FRAME
            channel_count = self.CHANNELS
        else:
            frames = self.packet_get_nb_frames(data)
            channel_count = self.CHANNELS
            samples_per_frame = self.packet_get_samples_per_frame(data)
            frame_size = frames * samples_per_frame

        pcm = (ctypes.c_int16 * (frame_size * channel_count * ctypes.sizeof(ctypes.c_int16)))()
        pcm_ptr = ctypes.cast(pcm, c_int16_ptr)

        ret = _lib.opus_decode(self._state, data, len(data) if data else 0, pcm_ptr, frame_size, fec)

        return array.array("h", pcm[: ret * channel_count]).tobytes()

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
                p = subprocess.run(args, stdout=subprocess.PIPE, input=input_audio_file,text=True, encoding="utf-8")
                #print(p.stdout)
                try:
                    output = p.stdout.split("### read waveform input")[1].split("\n\n")
                except IndexError:
                    output = list()
                for i in output:
                    try:
                        sentence = i.split("sentence1:")[1].split("\n")[0].replace(" ", "")
                    except IndexError:
                        continue
                    print(sentence)
                    cmd = sentence.translate(str.maketrans({chr(0xFF01 + i): chr(0x21 + i) for i in range(94)}))
                    msg=self.ctx.message
                    userid = self.ws.ssrc_map[ssrc]["user_id"]
                    author = msg.guild.get_member(userid)
                    #print(msg.author.name)
                    msg.author = author
                    msg.content = cmd
                    #暫定的に読み取った文字をそのままコマンドとして実行
                    await self.bot.process_commands(msg)
                os.remove(input_audio_filefm)
                os.remove(input_audio_file)
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
                self.is_recording[ssrc] = True
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
        if voice_client.guild.id in self.now:
            await self.ctxs[ctx.guild.id].send("一人ぼっちになったので切断しました。")
            voice_client.disco()
            await voice_client.disconnect()
            self._closing[ctx.guild.id] = True

    @commands.Cog.listener()
    async def on_voice_leave(self, member: discord.Member, _, __):
        if member.id == self.bot.user.id and member.guild.id in self._closing \
                and not self._closing[member.guild.id]:
            await self.ctxs[member.guild.id].send("ｷｬｯ、誰かにVCから蹴られたかバグが発生しました。")
            voice = get(self.bot.voice_clients, guild=member.guild)
            voice.disco()
            self._closing[member.guild.id] = True

def setup(bot):
    return bot.add_cog(vcnt(bot))