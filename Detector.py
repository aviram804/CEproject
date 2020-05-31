import numpy as np
import PacketPerTime
from PacketsPerInterval import PacketsPerInterval
import Intrusions
from BrainDataChunk import BrainDataChunk

ALIGNMENT_FACTOR = 4


def update(chunk1, chunk2):
    n1 = chunk1.num_of_updates
    n2 = chunk2.num_of_updates
    x1 = chunk1.mean
    x2 = chunk2.mean
    s1 = chunk1.variance
    s2 = chunk2.variance

    if chunk1.num_of_updates + chunk2.num_of_updates == 0:
        return
    total_data = chunk1.get_total_data() + chunk2.get_total_data()
    chunk1.mean = int(total_data / (chunk1.num_of_updates + chunk2.num_of_updates))
    d2 = x2 - chunk1.mean
    d1 = x1 - chunk1.mean
    chunk1.variance = (n1 * (s1 + d1 * d1) + n2 * (s2 + d2 * d2)) / (n1 + n2)
    chunk1.num_of_updates += chunk2.num_of_updates


def sum_ip_for_interval(ip, start_time, interval):
    """
    :param ip: string
    :param start_time: int - start time of ip in interval
    :param interval: PacketPerTimeInterval
    :return: mean sent, mean received per interval
    """
    chunk_sent = BrainDataChunk(0, 0, 0)
    chunk_received = BrainDataChunk(0, 0, 0)
    for i in range(start_time, len(interval)):
        packet_per_time = interval[i]
        if ip in packet_per_time.packets_map:
            update(chunk_sent, packet_per_time.packets_map[ip][PacketPerTime.SENT])
            update(chunk_received, packet_per_time.packets_map[ip][PacketPerTime.RECEIVED])
    return chunk_sent, chunk_received


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


STANDARD_DEVIATION = 2


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
            data_sent, data_received = sum_ip_for_interval(curr_ip, time, interval)
            brain_sent, brain_received = sum_ip_for_interval(curr_ip, 0, brain_interval)
            # testing curr_ip
            # Key=(IPSent, Received) Value=(BrainDataChunk)
            # data_sent, _ = sum_ip_for_interval_2_ip_key(curr_ip, time, interval)
            # brain_sent, brain_var = sum_ip_for_interval_2_ip_key(curr_ip, 0, brain_interval)

            if data_sent.mean > brain_sent.mean + STANDARD_DEVIATION * (brain_sent.variance ** 0.5):

                if brain_sent.num_of_updates < 3:
                    continue
                intrusion = Intrusions.IPOverSent(curr_ip, intrusion_time, data_sent)

                print(intrusion)
                print("brain_sent=", brain_sent, " with variance_sent=", brain_sent.variance)

                intrusions.add(intrusion)

            # if data_received > brain_received + 2*(variance_received ** 0.5):
            #     intrusions.add(Intrusions.IPOverReceived(curr_ip, intrusion_time, data_received))

            checked_ips.add(curr_ip)

    return intrusions



