import numpy as np
import PacketPerTime
from PacketsPerInterval import PacketsPerInterval
import Intrusions

ALIGNMENT_FACTOR = 4


def sum_ip_for_interval(ip, start_time, interval):
    """
    :param ip: string
    :param start_time: int - start time of ip in interval
    :param interval: PacketPerTimeInterval
    :return: mean sent, mean received per interval
    """
    data_sent = 0
    data_received = 0
    var_sent = 0
    var_received = 0
    for i in range(start_time, len(interval)):
        packet_per_time = interval[i]
        if ip in packet_per_time.packets_map:
            var_sent = max(var_sent, packet_per_time.packets_map[ip][PacketPerTime.SENT].get_variance())
            var_received = max(var_sent, packet_per_time.packets_map[ip][PacketPerTime.RECEIVED].get_variance())
            data_sent = max(data_sent, packet_per_time.packets_map[ip][PacketPerTime.SENT].get_amount_data())
            data_received = max(data_received, packet_per_time.packets_map[ip][PacketPerTime.RECEIVED].get_amount_data())
    return data_sent, data_received, var_sent, var_received


def sum_ip_for_interval_2_ip_key(ip, start_time, interval):
    """
    :param ip: string
    :param start_time: int - start time of ip in interval
    :param interval: PacketPerTimeInterval
    :return: mean sent, mean received per interval
    """
    data_sent = 0
    var_sent = 0
    for i in range(start_time, len(interval)):
        packet_per_time = interval[i]
        if ip in packet_per_time.packets_map:
            var_sent = max(var_sent, packet_per_time.packets_map[ip].get_variance())
            data_sent = max(data_sent, packet_per_time.packets_map[ip].get_amount_data())
    return data_sent, var_sent


STANDARD_DEVIATION = 4


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
            # Key=IP Value=(Sent,Received)
            # data_sent, data_received, _, _ = sum_ip_for_interval(curr_ip, time, interval)
            # brain_sent, brain_received, brain_var, variance_received = sum_ip_for_interval(curr_ip, 0, brain_interval)

            # testing curr_ip
            # Key=(IPSent, Received) Value=(BrainDataChunk)
            data_sent, _ = sum_ip_for_interval_2_ip_key(curr_ip, time, interval)
            brain_sent, brain_var = sum_ip_for_interval_2_ip_key(curr_ip, 0, brain_interval)

            if data_sent > brain_sent + STANDARD_DEVIATION*(brain_var ** 0.5):

                intrusion = Intrusions.IPOverSent(curr_ip, intrusion_time, data_sent)

                print(intrusion)
                print("brain_sent=", brain_sent, " with variance_sent=", brain_var)

                intrusions.add(intrusion)

            # if data_received > brain_received + 2*(variance_received ** 0.5):
            #     intrusions.add(Intrusions.IPOverReceived(curr_ip, intrusion_time, data_received))

            checked_ips.add(curr_ip)

    return intrusions



