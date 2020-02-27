import json
import numpy as np

# PARAMETRIC
NUM_IPS = 200
NUM_DIFFERENT_IPS = 50
SECONDS = 1000
FUNC = np.random.randint


# NOT PARAMETRIC
DATA_TYPES = ["B", "KB", "MB", "GB"]
IP_RANGE = (100, 300)
LOW = 0
HIGH = 1


def my_size_func():
    return np.random.randint(1, 100)


def my_update_func():
    return np.random.randint(1, 30)


def my_type_func():
    p = np.random.randint(1, 100)
    if p <= 50:
        return "B"
    if p <= 85:
        return "KB"
    if p <= 98:
        return "MB"
    return "GB"


def rand_ip():
    return str(np.random.randint(IP_RANGE[LOW], IP_RANGE[HIGH]))


def create_data(num_ips, seconds, num_different_ips, size_func, updates_func, type_func):
    ips = set()
    while len(ips) < num_ips:
        ip = rand_ip() + '.' + rand_ip() + '.' + rand_ip() + '.' + rand_ip()
        ips.add(ip)

    ips = list(ips)
    brain_dict = {}
    for i in range(seconds):
        indexes = np.random.choice(num_ips, num_different_ips)
        time_dict = {}
        for idx in indexes:
            sent = "(" + str(size_func()) + type_func() + ", updates=" + str(updates_func()) + ")"
            receive = "(" + str(size_func()) + type_func() + ", updates=" + str(updates_func()) + ")"
            time_dict[ips[idx]] = [sent, receive]

    return brain_dict
#
# with open("C:\\Users\\aviram\\PycharmProjects\\engineerProject\\data", 'w') as json_file:
#     json.dump(dict, json_file)


create_data(NUM_IPS, SECONDS, NUM_DIFFERENT_IPS, my_size_func, my_update_func, my_type_func)
