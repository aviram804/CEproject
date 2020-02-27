import json
import  numpy as np

SECONDS = 1000

DATA_TYPES = ["B", "KB", "MB", "GB"]

NUM_IPS = 200

ips = []
for i in range(NUM_IPS):
    ip = str(np.random.randint(100, 300)) + '.' + str(np.random.randint(100, 300)) + '.' + str(np.random.randint(
        100, 300)) + '.' + str(np.random.randint(100, 300))
    ips.append(ip)


dict = {}
for i in range(SECONDS):
    indexes = np.random.choice(NUM_IPS, 50)
    time_dict = {}
    for idx in indexes:
        sent = "(" + str(np.random.randint(1,100)) + DATA_TYPES[np.random.randint(0,3)] + ", updates=" + str(
            np.random.randint(1,30)) + ")"
        receive = "(" + str(np.random.randint(1, 100)) + DATA_TYPES[np.random.randint(0, 3)] + ", updates=" + str(
            np.random.randint(1, 30)) + ")"
        time_dict[ips[idx]] = [sent, receive]
    dict[str(i)] = time_dict
pass
#
# with open("C:\\Users\\aviram\\PycharmProjects\\engineerProject\\data", 'w') as json_file:
#     json.dump(dict, json_file)

