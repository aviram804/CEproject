import numpy as np
from Detector import detect_intrusion
from BrainDataChunk import BrainDataChunk
import Brain
import Intrusions

SENT = 0
RECEIVED = 1


class PacketPerTime:

    def __init__(self, packets, time):
        """

        :param packets: dictionary, key=IP, value=tuple(sent, received, num of updates)
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
        :return:
        """
        packets = {}
        for ip, tup in obj_map.items():
            Brain.IP_SET.add(ip)
            packets[ip] = (BrainDataChunk.get_from_str(tup[SENT]), BrainDataChunk.get_from_str(tup[RECEIVED]))
        return PacketPerTime(packets, time)

    def update(self, other):
        """
        updates petTime in given other per time
        :param other: PacketPerTime
        :return: updated PacketPerTime
        """
        intrusions = []
        if other is None:
            return intrusions
        for ip, tup in other.packets_map.items():
            intrusion = self.add_chunk(ip, tup)
            if intrusion is not None:
                intrusions.append(intrusion)
        return intrusions

    def add_chunk(self, ip, tup):
        """
        adds chunk to chunks per time
        :param ip: ip to update
        :param tup: BrainDataChunk tuple, sent received
        """
        if ip not in self.packets_map:
            self.packets_map[ip] = tup
            return Intrusions.FoundNewIP(ip)
        self.packets_map[ip][SENT].update(tup[SENT])
        self.packets_map[ip][RECEIVED].update(tup[RECEIVED])

    def add_packet(self, packet):
        """
        updates 2 ips in given PacketChunk object
        :param packet: PacketChunk, sender receiver ip's and amount of data
        :return:
        """
        chunk = BrainDataChunk("B", packet.amount, 1)
        empty = BrainDataChunk("B", 0, 0)
        sender = chunk, empty
        reciever = empty, chunk
        self.add_chunk(packet.sender, sender)
        self.add_chunk(packet.reciever, reciever)
