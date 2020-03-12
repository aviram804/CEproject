import PacketPerTime
from BrainDataChunk import BrainDataChunk
from PacketsPerInterval import PacketsPerInterval
import json


MALICIOUS_IP = "malicious_ips"


class Brain:

    def __init__(self, data_map, ip_set, malicious_ips):
        """
        :param data_map: Dictionary-> Key=int-time   Value=PacketsPerTime
        :param ip_set: set of all IP's
        :param malicious_ips: set of malicious IP's
        """
        self.data_map = data_map
        self.ip_set = ip_set
        self.malicious_ips = malicious_ips

    def generate_jason(self, dest):
        """
        :param dest: path to place csv
        :return:
        """
        general_dict = {}
        for key, value in self.data_map.items():
            general_dict[key] = value.dump()
        general_dict[MALICIOUS_IP] = self.malicious_ips
        with open(dest, 'w') as json_file:
            json.dump(general_dict, json_file)

    @staticmethod
    def generate_from_json(dest):
        """
        :param dest: path to place csv
        :return:
        """
        malicious_ips = None
        packets_per_time_dict = {}
        with open(dest, 'r') as f:
            d = json.load(f)
        for key, value in d.items():
            if key == MALICIOUS_IP:
                malicious_ips = value
                continue
            packets_per_time_dict[key] = PacketPerTime.PacketPerTime.from_json(value, key)
        return Brain(packets_per_time_dict, PacketPerTime.IP_SET, malicious_ips)

    def update(self, packets_per_time):
        """
        updates packet_per_time  inside Brain
        :param packets_per_time: PacketPerTime
        :return: list of intrusions detected (new, malicious ip's)
        """
        if packets_per_time.time not in self.data_map:
            self.data_map[packets_per_time.time] = packets_per_time
            return
        self.data_map[packets_per_time.time].update(packets_per_time)

    def get_interval(self, current_time, interval):
        """
        :param current_time: start time of the interval
        :param interval: int, length of the interval
        :return: PacketsPerTime interval represents given times
        """
        packet_interval = PacketsPerInterval([])
        for i in range(interval):
            time = current_time + i
            if time not in self.data_map.keys():
                packet_interval.update(PacketPerTime.PacketPerTime({}, time))
                continue
            packet_interval.update(self.data_map[time])
        return packet_interval

    def add_malicious_ips(self, ip):
        self.malicious_ips.add(ip)

    def is_malicious_ips(self, ip):
        return ip in self.malicious_ips
