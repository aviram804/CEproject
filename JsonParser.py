import json
import numpy as np
from BrainDataChunk import BrainDataChunk
from Brain import Brain
from PacketChunk import *
import random
import Intrusions

SET_SIZE = BrainDataChunk.get_scale_for_size
DATA_TYPES = BrainDataChunk.TYPES
B = BrainDataChunk.B
KB = BrainDataChunk.KB
MB = BrainDataChunk.MB
GB = BrainDataChunk.GB

#############################################
#                PARAMETRIC                 #
#############################################

NUM_IPS = 10
NUM_DIFFERENT_IPS = 10
SECONDS = 50
FUNC = np.random.randint

BYTES_PERCENT = 50
KB_PERCENT = 45
MB_PERCENT = 4

SMALL_INTRUSION = 2
LARGE_INTRUSION = 50

FILE_NAME = "C:\\Users\\USER\\Documents\\Mypythons\\CEproject\\data"
MALICIOUS_IP = "malicious_ips"

#############################################
#              NOT PARAMETRIC               #
#############################################


IP_RANGE = (100, 300)
LOW = 0
HIGH = 1

MEAN = 500
VAR = 1000

REGULAR_SIZE = False
INTRUSION_SIZE = True

size_dict = {}

SIZE_FUNC = np.random.normal


def my_size_func():
    """
    randomized function for packet size
    :return: int
    """
    # return np.random.randint(1, 100)
    mean = np.random.randint(MEAN - VAR, MEAN + VAR)
    var = np.random.randint(0, 2*VAR)
    return lambda: abs(int(np.random.normal(mean, var))), var
    # return abs(int(np.random.normal(mean, var)))


# ALPHA = intrusion increased mean size
ALPHA = 100
# BETA = intrusion increased var size
BETA = 1


def intrusion_size_func():
    """
    randomized function for intrusion packet size
    :return: int
    """
    mean = MEAN * ALPHA
    var = VAR * BETA
    return abs(int(np.random.normal(mean, var)))


def my_update_func():
    """
    randomized function for number of updates
    :return: int
    """
    return np.random.randint(1000, 3000)


def rand_ip():
    """
    randomized function for ip generation
    :return:
    """
    def get_rand():
        return str(np.random.randint(IP_RANGE[LOW], IP_RANGE[HIGH]))
    return get_rand() + '.' + get_rand() + '.' + get_rand() + '.' + get_rand()


def create_data(num_ips, seconds, num_different_ips, size_func, updates_func):
    """
    randomized data creator
    :param num_ips: number of different ips in the data
    :param seconds: number of seconds to have in the data
    :param num_different_ips: number of different ips per second
    :param size_func: randomized function to get size of packet for each iteration
    :param updates_func:  randomized function to get number of updates for packet
    :return: python dictionary to dump json values.
    """
    ips = set()
    while len(ips) < num_ips:
        ip = rand_ip()
        ips.add(ip)

    malicious_ips = set()
    while len(malicious_ips) < 10:
        ip = rand_ip()
        if ip in ips:
            continue
        malicious_ips.add(ip)

    ips = list(ips)

    for ip in ips:
        size_dict[ip] = size_func()

    brain_dict = {}
    for i in range(seconds):
        time_dict = {}
        indexes = np.random.choice(num_ips, num_different_ips, replace=False)
        for idx in indexes:
            size, data_type = SET_SIZE(size_dict[ips[idx]][0]())
            sent = "(" + str(size) + data_type + "," + " var=" + str(size_dict[ips[idx]][1]) + " updates=" + str(updates_func()) + ")"
            size, data_type = SET_SIZE(size_dict[ips[idx]][0]())
            receive = "(" + str(size) + data_type + "," + " var=" + str(size_dict[ips[idx]][1]) + " updates=" + str(updates_func()) + ")"
            time_dict[ips[idx]] = [sent, receive]

        brain_dict[i] = time_dict
    brain_dict[MALICIOUS_IP] = list(malicious_ips)
    return brain_dict


CHOSE_IP_PERCENT = 98
RAND_IP_PERCENT = 1


def get_ip(ips, malicious_ips):
    """
    Randomly choose ip from:
    :param ips: all IPs in Brain
    :param malicious_ips: all malicious IPs in Brain
    :return: random IP
    """
    ips = list(ips)
    chooser = random.randint(0, 100)
    if chooser <= CHOSE_IP_PERCENT:
        rand = random.randint(0, len(ips))
        return ips[rand - 1]
    if chooser <= (CHOSE_IP_PERCENT + RAND_IP_PERCENT):
        return rand_ip()
    rand = random.randint(0, len(malicious_ips))
    return malicious_ips[rand - 1]


def get_size_for_ip(ip, size_type):
    if ip in size_dict.keys():
        if size_type == REGULAR_SIZE:
            return size_dict[ip][0]()
        return size_dict[ip][0]() * np.random.randint(SMALL_INTRUSION, LARGE_INTRUSION)
    return (my_size_func()[0])()


def get_chunk(time, ips, malicious_ips, size_func_type):
    """
    creates a single chunk with time stamp
    :param time: int, time stamp
    :param ips: all IPs in Brain
    :param malicious_ips: all malicious IPs in Brain
    :param size_func_type: regular data flow or intrusion data flow
    :return: PacketChunk - has a sender, a receiver, size and time
    """
    sender = get_ip(ips, malicious_ips)
    receiver = sender
    while receiver == sender:
        receiver = get_ip(ips, malicious_ips)
    size = get_size_for_ip(sender, size_func_type)
    return PacketChunk(sender, receiver, size, time)


IPS_PER_TIME = 10


def write_packet_chunks(ips, malicious_ips):
    """
    generates packets according to the ips presented in Brain - test tool
    :param ips: all IPs in Brain
    :param malicious_ips: all malicious IPs in Brain
    :return: new input data
    """
    list_chuncks = []
    malicious = list(malicious_ips)
    ips_list = list(ips)

    for i in range(SECONDS):
        for j in range(IPS_PER_TIME):
            list_chuncks.append(get_chunk(i, ips_list, malicious, my_size_func))
    return list_chuncks, None


INTRUSION_PERCENTAGE = 9900


def write_intrusion_packet_chunk(ips, malicious_ips):
    """
    generates packets according to the ips presented in Brain - with percentage for intrusion
    :param ips: all IPs in Brain
    :param malicious_ips: all malicious IPs in Brain
    :return: new input data, intrusions
    """
    list_chuncks = []
    intrusion_chunks = set()
    malicious = list(malicious_ips)
    ips_list = list(ips)

    for i in range(SECONDS):
        for j in range(IPS_PER_TIME):
            size_func = REGULAR_SIZE
            rand = random.randint(0, 10000)
            if rand >= INTRUSION_PERCENTAGE:
                size_func = INTRUSION_SIZE

            chunk = get_chunk(i, ips_list, malicious, size_func)
            list_chuncks.append(chunk)

            if rand >= INTRUSION_PERCENTAGE:
                intrusion_chunks.add(Intrusions.IPOverReceived(chunk.receiver, chunk.time, chunk.amount))
                intrusion_chunks.add(Intrusions.IPOverSent(chunk.sender, chunk.time, chunk.amount))
    # returns list of chunks to run on, and map of IP and list of intrusion at seconds
    return list_chuncks, intrusion_chunks


def json_get_brain_chunks(packet_func):
    """

    :return:
    """
    data_dict = create_data(NUM_IPS, SECONDS, NUM_DIFFERENT_IPS, my_size_func, my_update_func)
    with open(FILE_NAME, 'w') as json_file:
        json.dump(data_dict, json_file)
    brain = Brain.generate_from_json(FILE_NAME)
    list_chunks, intrusions = packet_func(brain.ip_map, brain.malicious_ips)
    return brain, list_chunks, intrusions
