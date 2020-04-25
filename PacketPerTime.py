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
        for ip, tup in self.packets_map.items():
            out_map[ip] = (tup[SENT].get_str(), tup[RECEIVED].get_str())
        return out_map

    @staticmethod
    def from_json(obj_map, time):
        """

        :param obj_map:
        :param time:
        :return:
        """
        packets = {}
        for ip, tup in obj_map.items():
            IP_SET.add(ip)
            packets[ip] = (BrainDataChunk.get_from_str(tup[SENT]), BrainDataChunk.get_from_str(tup[RECEIVED]))
        return PacketPerTime(packets, time)

    def update(self, other):
        """
        updates petTime in given other per time
        :param other: PacketPerTime
        :return: updated PacketPerTime
        """
        if other is None:
            return
        for ip, tup in other.packets_map.items():
            self.add_chunk(ip, tup)

    def add_chunk(self, ip, tup):
        """
        adds chunk to chunks per time
        :param ip: ip to update
        :param tup: (BrainDataChunk, BrainDataChunk) tuple, sent received
        """
        if ip not in self.packets_map:
            self.packets_map[ip] = tup
            return
        self.packets_map[ip][SENT].update(tup[SENT])
        self.packets_map[ip][RECEIVED].update(tup[RECEIVED])

    def add_packet(self, packet):
        """
        updates 2 ips in given PacketChunk object
        :param packet: PacketChunk, sender receiver ip's and amount of data
        :return:
        """
        chunk = BrainDataChunk(packet.amount, 1)
        empty = BrainDataChunk(0, 0)
        sender = chunk, empty
        receiver = empty, chunk
        self.add_chunk(packet.sender, sender)
        self.add_chunk(packet.receiver, receiver)
