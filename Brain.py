import PacketPerTime
from BrainDataChunk import BrainDataChunk
from PacketsPerInterval import PacketsPerInterval
import json
from random import randint

MALICIOUS_IP = "malicious_ips"


class Brain:

    COUNTRY = 0
    SIZE_FUNC = 1

    def __init__(self, data_map, ip_set, malicious_ips):
        """
        :param data_map: Dictionary-> Key=int-time   Value=PacketsPerTime
        :param ip_set: set of all IP's
        :param malicious_ips: set of malicious IP's
        """
        self.data_map = data_map
        self.ip_set = ip_set
        self.malicious_ips = malicious_ips
        self.ip_country_map = {}

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
        print("Generate Brain from JSON")
        malicious_ips = None
        packets_per_time_dict = {}
        with open(dest, 'r') as f:
            d = json.load(f)
        for key, value in d.items():
            if key == MALICIOUS_IP:
                malicious_ips = value
                continue
            packets_per_time_dict[int(key)] = PacketPerTime.PacketPerTime.from_json(value, key)
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
                print("WARNING - time", current_time + i, "not in Brain")
                continue
            packet_interval.update(self.data_map[time])
        return packet_interval

    def add_malicious_ips(self, ip):
        """
        adds ip to malicious_ips set
        :param ip: string, IP
        """
        self.malicious_ips.add(ip)

    def is_malicious_ips(self, ip):
        """
        :param ip: string, IP
        :return: boolean, is malicious ip
        """
        return ip in self.malicious_ips

    def load_ip_country_map(self, filename):
        """
        loads ip to country map using filename
        :param filename: string
        """
        pass

# COUNTRIES PERCENTAGE:
    PERCENTAGE = [
        [88, "Israel"],
        [3, "China"],
        [3, "USA"],
        [3, "GBR"],
        [3, "Germany"]
    ]

    def generate_ip_country_map(self):
        """
        randomly generate ip to country map - test tool
        """
        brain_map = Brain.PERCENTAGE
        for ip in self.ip_set:
            chooser = randint(0, 100)
            current = 0
            for i in range(len(brain_map)):
                current += brain_map[i][0]
                if chooser <= current:
                    self.ip_country_map[ip] = brain_map[i][1]
                    break
