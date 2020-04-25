import numpy as np
import PacketPerTime
from PacketsPerInterval import PacketsPerInterval
import Intrusions

ALIGNMENT_FACTOR = 10


def sum_ip_for_interval(ip, start_time, interval):
    """
    :param ip: string
    :param start_time: int - start time of ip in interval
    :param interval: PacketPerTimeInterval
    :return: mean sent, mean received per interval
    """
    data_sent = 0
    data_received = 0
    for i in range(start_time, len(interval)):
        packet_per_time = interval[i]
        if ip in packet_per_time.packets_map:
            data_sent += packet_per_time.packets_map[ip][PacketPerTime.SENT].get_amount_data()
            data_received += packet_per_time.packets_map[ip][PacketPerTime.RECEIVED].get_amount_data()
    data_sent /= len(interval)
    data_received /= len(interval)
    return data_sent, data_received


def detect_intrusion(per_time_brain_interval, per_time_interval):
    """
    detect intrusion between 2 packets per time intervals
    :param per_time_brain_interval: PacketPerTimeInterval object from our brain
    :param per_time_interval: PacketPerTimeInterval object that represent current time
    :return:
    """
    checked_ips = set()
    intrusions = set()
    intrusion_time = per_time_interval.packets[0].time
    interval = per_time_interval.packets
    brain_interval = per_time_brain_interval.packets

    for time in range(len(interval)):
        for curr_ip in interval[time].packets_map:

            if curr_ip in checked_ips:
                continue

            # testing curr_ip
            data_sent, data_received = sum_ip_for_interval(curr_ip, time, interval)
            brain_sent, brain_received = sum_ip_for_interval(curr_ip, 0, brain_interval)

            if brain_sent > 0 and data_sent > ALIGNMENT_FACTOR * brain_sent:
                intrusions.add(Intrusions.IPOverSent(curr_ip, intrusion_time, data_sent))

            if brain_received > 0 and data_received > ALIGNMENT_FACTOR * brain_received:
                intrusions.add(Intrusions.IPOverReceived(curr_ip, intrusion_time, data_received))

            checked_ips.add(curr_ip)

    return intrusions



