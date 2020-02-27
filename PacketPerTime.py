import numpy as np
from Detector import detect_intrusion
from BrainDataChunk import BrainDataChunk

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
            packets[ip] = (BrainDataChunk.get_from_str(tup[SENT]), BrainDataChunk.get_from_str(tup[RECEIVED]))
        return PacketPerTime(packets, time)

    def update(self, other):
        """

        :param other:
        :return:
        """
        if other is None:
            return self
        for ip, tup in other.packets_map.items():

            if ip not in self.packets_map:
                self.packets_map[ip] = tup
                continue

            self.packets_map[ip][SENT].update(tup[SENT])
            self.packets_map[ip][RECEIVED].update(tup[RECEIVED])
