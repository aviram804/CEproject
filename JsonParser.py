import json
import numpy as np
from BrainDataChunk import BrainDataChunk
import Brain

SET_SIZE = BrainDataChunk.get_scale_for_size
DATA_TYPES = BrainDataChunk.TYPES
B = BrainDataChunk.B
KB = BrainDataChunk.KB
MB = BrainDataChunk.MB
GB = BrainDataChunk.GB

#############################################
#                PARAMETRIC                 #
#############################################

NUM_IPS = 200
NUM_DIFFERENT_IPS = 50
SECONDS = 1000
FUNC = np.random.randint

BYTES_PERCENT = 50
KB_PERCENT = 45
MB_PERCENT = 4

FILE_NAME = "C:\\Users\\USER\\Documents\\Mypythons\\data"

#############################################
#              NOT PARAMETRIC               #
#############################################


IP_RANGE = (100, 300)
LOW = 0
HIGH = 1


def my_size_func():
    """
    randomized function for packet size
    :return: int
    """
    # return np.random.randint(1, 100)
    mean = 500
    var = 300
    return abs(int(np.random.normal(mean, var)))


def my_update_func():
    """
    randomized function for number of updates
    :return: int
    """
    return np.random.randint(1, 30)


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

    ips = list(ips)
    brain_dict = {}
    for i in range(seconds):
        time_dict = {}
        indexes = np.random.choice(num_ips, num_different_ips)
        for idx in indexes:
            size, data_type = SET_SIZE(size_func())
            sent = "(" + str(size) + data_type + ", updates=" + str(updates_func()) + ")"
            size, data_type = SET_SIZE(size_func())
            receive = "(" + str(size) + data_type + ", updates=" + str(updates_func()) + ")"
            time_dict[ips[idx]] = [sent, receive]

        brain_dict[i] = time_dict
    brain_dict[Brain.MALICIOUS_IP] = set()
    return brain_dict


data_dict = create_data(NUM_IPS, SECONDS, NUM_DIFFERENT_IPS, my_size_func, my_update_func)
with open(FILE_NAME, 'w') as json_file:
    json.dump(data_dict, json_file)
