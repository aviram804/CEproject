import numpy as np
import PacketPerTime
from PacketsPerInterval import PacketsPerInterval
import Intrusions


def find_new_ips(to_check, ips, malicious_ips):

    for ip in to_check:
        if ip not in ips:
            err = Intrusions.FoundNewIP(ip)
            err.get_error()
        if ip in malicious_ips:
            err = Intrusions.FoundMaliciousIP(ip)
            err.get_error()


def detect_intrusion(packet1, packet2, ips, malicious_ips):
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


