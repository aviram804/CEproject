import numpy as np
import PacketPerTime
from PacketsPerInterval import PacketsPerInterval
import Intrusions

def detect_intrusion(packet1, packet2):
    """
    detect intrusion between 2 packets per time intervals
    :param packet1: PacketPerTimeInterval
    :param packet2: PacketPerTimeInterval
    :return:
    """
    for i in range(len(packet2)):
        packet_per_time1 = packet1[i]
        packet_per_time2 = packet2[i]
        for ip, tup in packet_per_time1.packets_map:
            sent, received = tup


