import struct
import time
from collections import defaultdict
from discord.opus import Decoder as DiscordDecoder
from discord.opus import exported_functions, OpusError, c_float_ptr
import sys
import ctypes
import os
import wave
import array

c_int_ptr = ctypes.POINTER(ctypes.c_int)
c_int16_ptr = ctypes.POINTER(ctypes.c_int16)
# c_float_ptr = ctypes.POINTER(ctypes.c_float)


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
            print("Error assigning check function to %s", func)

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
                # 該当するパケットがなかった場合、破損していたとみなす
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
        file = str(ssrc) + "-" + str(time.time()) + ".wav"
        wav = wave.open(file, "wb")
        wav.setnchannels(Decoder.CHANNELS)
        wav.setsampwidth(Decoder.SAMPLE_SIZE // Decoder.CHANNELS)
        wav.setframerate(Decoder.SAMPLING_RATE)
        decoder = Decoder()
        for packet in self.queue.queues[ssrc]:
            try:
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
            except Exception:
                pass
        wav.close()
        # file.seek(0)
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

        return array.array('f', pcm[:ret * channel_count]).tobytes()

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
