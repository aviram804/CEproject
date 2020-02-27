import numpy as np
import PacketPerTime


def detect_intrusion(packet1, packet2):
    """
    detect intrusion between 2 packets per time
    :param packet1: PacketPetTimeInterval
    :param packet2: PacketPetTimeInterval
    :return:
    """
    return packet1 == packet2


