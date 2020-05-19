import numpy as np
from Detector import detect_intrusion
from BrainDataChunk import BrainDataChunk


SENT = 0
RECEIVED = 1
IP_SET = set()


class PacketPerTime:

    def __init__(self, packets, time):
        """

        :param packets: dictionary, key=IP, value=tuple(BrainDataChunk=sent, BrainDataChunk=received)
        """
        self.time = time
        self.packets_map = packets

    def dump(self):
        """
        :return:
        """
        out_map = {}
        # Key=IP Value=(Sent,Received)
        for ip, tup in self.packets_map.items():
            out_map[ip] = (tup[SENT].get_str(), tup[RECEIVED].get_str())

        # Key=(IPSent, Received) Value=(BrainDataChunk)
        # for ip, brainDataChunk in self.packets_map.items():
        #     out_map[ip] = brainDataChunk.get_str()

        return out_map

    @staticmethod
    def from_json(obj_map, time):
        """

        :param obj_map:
        :param time:
        :return:
        """

        packets = {}
        # Key=IP Value=(Sent,Received)
        for ip, tup in obj_map.items():
            IP_SET.add(ip)
            packets[ip] = (BrainDataChunk.get_from_str(tup[SENT]), BrainDataChunk.get_from_str(tup[RECEIVED]))

        # Key=(IPSent, Received) Value=(BrainDataChunk)
        # for ip, brainDataChunk in obj_map.items():
        #     split_index = 0
        #     for c in ip:
        #         split_index += 1
        #         if c == ':':
        #             break
        #     IP_SET.add(ip[:split_index])
        #     IP_SET.add(ip[split_index+1:])
        #     packets[ip] = BrainDataChunk.get_from_str(brainDataChunk)

        return PacketPerTime(packets, time)

    def update(self, other):
        """
        updates petTime in given other per time
        :param other: PacketPerTime
        :return: updated PacketPerTime
        """
        if other is None:
            return

        # Key=IP Value=(Sent,Received)
        for ip, tup in other.packets_map.items():
            self.add_chunk(ip, tup)

        # Key=(IPSent, Received) Value=(BrainDataChunk)
        # for ip, brainDataChunk in other.packets_map.items():
        #     self.add_chunk(ip, brainDataChunk)

    def add_chunk(self, ip, chunk):
        """
        adds chunk to chunks per time
        :param ip: ip to update
        :param chunk: (BrainDataChunk, BrainDataChunk) tuple, sent received
        """
        if ip not in self.packets_map:
            self.packets_map[ip] = chunk
            return

        # Key=IP Value=(Sent,Received)
        self.packets_map[ip][SENT].update(chunk[SENT])
        self.packets_map[ip][RECEIVED].update(chunk[RECEIVED])

        # Key=(IPSent, Received) Value=(BrainDataChunk)
        # self.packets_map[ip].update(chunk)

    def add_packet(self, packet):
        """
        updates 2 ips in given PacketChunk object
        :param packet: PacketChunk, sender receiver ip's and amount of data
        :return:
        """
        # Key=IP Value=(Sent,Received)
        chunk = BrainDataChunk(packet.amount, var=0, updates=1)
        empty = BrainDataChunk(amount=0, var=0, updates=1)
        sender = chunk, empty
        receiver = empty, chunk
        self.add_chunk(packet.sender, sender)
        self.add_chunk(packet.receiver, receiver)

        # Key=(IPSent, Received) Value=(BrainDataChunk)
        # chunk = BrainDataChunk(packet.amount, var=0, updates=1)
        # ips = packet.sender + ":" + packet.receiver
        # self.add_chunk(ips, chunk)
