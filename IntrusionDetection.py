import pyshark
from PacketPerTime import PacketPerTime
from Brain import Brain
from Detector import detect_intrusion
from numpy import random
from PacketsPerInterval import PacketsPerInterval
import JsonParser
from matplotlib import pyplot as plt
from PacketChunk import PacketChunk
from itertools import count
from Intrusions import IPOverSent
import csv
"""
this script parsing a pcapng file that generate on wireShark 
it create a chunk object from each packet that wireShark generate and then insert it 
to our database
"""


# packets = pyshark.FileCapture("C:\\Users\\aviram\\PycharmProjects\\WiresharkParser\\PacketsData.pcapng")

# packetsBase = ChunksBase.ChunksBase(5


def parse(packet):
    try:
        # time_in_sec = int(packet.frame_info.time[16:18]) * 60 + int(packet.frame_info.time[19:21])
        time_in_sec = int(packet.frame_info.time[19:21])
        return PacketChunk(packet.ip.addr, packet.ip.dst, int(packet.captured_length), time_in_sec)

    except:
        return None

TIME = 0


def paint_prec_recall_graph(precision, recall):
    # plotting the points
    plt.plot(precision, recall, label="Key=IP")
    # naming the x axis
    plt.xlabel('precision')
    # naming the y axis
    plt.legend()
    plt.ylabel('recall')
    plt.title('Precision vs Recall')
    plt.savefig("PrecisionRecall.png")
    plt.show()


def display_intrusions(detected_intrusions, created_intrusions, standard_deviation):
    """
    displays information graph for detected intrusions, compared to created ones
    :param detected_intrusions: List, detected intrusions, List of Intrusions objects
    :param created_intrusions: set, created intrusions
    """
    print("Detected intrusion length=", len(detected_intrusions),  " With Created intrusion length=", len(created_intrusions))
    true_positive = 0
    false_positive = 0
    false_negative = 0
    yellows = [[], []]
    blues = [[], []]
    reds = [[], []]
    painted = []
    for intrusion in detected_intrusions:

        true_positive = False
        for intrusion2 in created_intrusions:
            if intrusion2 == intrusion:
                true_positive = True
                break

        if true_positive:
            painted.append(intrusion)
            # print("True Positive")
            true_positive += 1
            blues[0].append(intrusion.time)
            blues[1].append(intrusion.amount_data)
            # plt.scatter(intrusion.time, intrusion.amount_data, color="blue", s=10)
            # painted.append(intrusion)
        else:
            # False Positive
            painted.append(intrusion)
            false_positive += 1
            painted.append(intrusion)
            reds[0].append(intrusion.time)
            reds[1].append(intrusion.amount_data)
            # painted.append(intrusion)
            # plt.scatter(intrusion.time, intrusion.amount_data, color="red", s=10)

    for intrusion in created_intrusions:
        detected_intrusion = False
        for intrusion2 in detected_intrusions:
            if intrusion2 == intrusion:
                detected_intrusion = True
                break

        if not detected_intrusion:
            # False Negative
            false_negative += 1
            painted.append(intrusion)
            yellows[0].append(intrusion.time)
            yellows[1].append(intrusion.amount_data)
            # plt.scatter(intrusion.time, intrusion.amount_data, color="yellow", s=10)

    if false_negative + true_positive != 0:
        recall = true_positive / (true_positive + false_negative)
    else:
        recall = 1

    if true_positive + false_positive != 0:
        precision = true_positive / (true_positive + false_positive)
    else:
        precision = 1

    plt.scatter(blues[0], blues[1], color="blue", s=10, label="blue")
    plt.scatter(yellows[0], yellows[1], color="yellow", s=10, label="yellow")
    plt.scatter(reds[0], reds[1], color="red", s=10, label="red")
    # print("For Standard_deviation=", standard_deviation, " Precision =", precision)
    # print("For Standard_deviation=", standard_deviation, "Recall =", recall)
    # naming the x axis
    plt.xlabel('Time')
    # naming the y axis
    plt.ylabel('Amount data for packet')
    plt.title("Intrusions with Standard Deviation " + str(standard_deviation))
    plt.legend(["True Positive", "False Negative", "False Positive"], loc="upper left")
    # plt.savefig("deviation" + str(standard_deviation) + ".png")
    plt.show()
    plt.close()
    return precision, recall

# brain:  BrainObj
# brain = Brain.generate_from_json(JsonParser.FILE_NAME)
# current_time = packets[0][TIME]


MILLION = 1000000

STANDARD_DEVIATIONS = [0.4, 0.5, 0.6, 0.8, 1, 1.2, 1.4, 1.6, 1.8, 2, 2.3, 2.6, 3, 3.5, 4]


def load_precision_recall():
    pre_list, rec_list = [], []
    updates = 0
    file = "prec_recal.csv"
    with open(file) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        row_count = 0
        for row in csv_reader:
            if row_count == 0:
                updates = int(row[0])
            elif row_count == 1:
                for pre in row:
                    if pre != "":
                        pre_list.append(float(pre))

            elif row_count == 2:
                for rec in row:
                    if rec != "":
                        rec_list.append(float(rec))

            row_count += 1

        return updates, pre_list, rec_list


def dump_precision_recall(pre_lst, rec_lst, updates):
    f = open('prec_recal.csv', 'w')
    f.write(str(updates))
    f.write("\n")
    for pre in pre_lst:
        f.write(str(pre))
        f.write(',')
    f.write("\n")
    for rec in rec_lst:
        f.write(str(rec))
        f.write(',')
    f.close()



# sharkFilePath = "learnable_data/2_sec_data_9.pcapng"
# sharkFilePaths = ["learnable_data/2_sec_data_2.pcapng"]
sharkFilePaths = ["learnable_data/2_sec_data_7_listening_to_youtube.pcapng", "learnable_data/2_sec_data_7_listening_to_youtube.pcapng"]
brainPath = "brainNewData2"

idx = count()
x_vals = []
y_vals = []


def merge_list(old_lst, new_lst, updates):
    out = []
    for i in range(len(old_lst)):
        num = (old_lst[i] * updates + new_lst[i]) / (updates + 1)
        out.append(num)
    return out

def find_intrusion():

    # pet_time_interval: PacketPerInterval - last 5 PacketsPerTime
    per_time_interval = PacketsPerInterval([])

    # Brain object, packets to run on.
    # brain, packets, ip_intrusions = JsonParser.json_get_brain_chunks(JsonParser.write_intrusion_packet_chunk)

    # brain = Brain({}, {}, ())

    brain = Brain.generate_from_json(brainPath)

    intrusions = [set() for _ in STANDARD_DEVIATIONS]
    ip_intrusions = set()
    fixed_time = 0

    for sharkFile in sharkFilePaths:
        packets = pyshark.FileCapture(sharkFile)

        index = 0
        while not parse(packets[index]):
            index += 1

        current_time = parse(packets[index]).time

        # current_time = 0
        per_time = PacketPerTime({}, current_time)

        all_packets = []
        for packet in packets:
            # translate to our object
            packet_chunk = parse(packet)

            # packet_chunk = packet

            if not packet_chunk:
                continue

            # OR: just use packet as it is if we are running on our data set
            # packet_chunk = packet
            # current_time = packet_chunk.time
            if packet_chunk.time == current_time:

                probability = 3
                rand = random.randint(0, 100)
                if rand < probability:
                    packet_chunk.amount *= 5
                    ip_intrusions.add(IPOverSent(packet_chunk.sender, current_time + fixed_time, packet_chunk.amount))

                per_time.add_packet(packet_chunk)
                continue

            to_update = per_time_interval.update(per_time)
            if to_update is not None:
                brain.update(to_update)
            all_packets.append(IPOverSent(packet_chunk.sender, packet_chunk.time, packet_chunk.amount))
            start_time = (current_time - 4) % 60
            brain_interval = brain.get_interval(start_time, PacketsPerInterval.INTERVAL)
            intrusion_time = current_time

            for i in range(len(STANDARD_DEVIATIONS)):
                deviation = STANDARD_DEVIATIONS[i]
                detected_intrusions = detect_intrusion(brain_interval, per_time_interval, intrusion_time, deviation)
                intrusions[i] = intrusions[i].union(detected_intrusions)
                if current_time == 61:
                    pass
            # print("Intrusions len for time:", current_time, " = ", len(intrusions))

            current_time += 1
            per_time = PacketPerTime({}, current_time)

        # fixed_time = current_time
        fixed_time += 40

    for packet_per_time in per_time_interval.packets:
        brain.update(packet_per_time)

    print("Done Detecting")

    # brain.generate_jason(brainPath)
    precision_lst = []
    recall_lst = []
    for i in range(len(STANDARD_DEVIATIONS)):
        precision, recall = display_intrusions(intrusions[i], ip_intrusions, STANDARD_DEVIATIONS[i])
        precision_lst.append(precision)
        recall_lst.append(recall)
    updates, old_precision_lst, old_recall_lst = load_precision_recall()
    precision_lst = merge_list(old_precision_lst, precision_lst, updates)
    recall_lst = merge_list(old_recall_lst, recall_lst, updates)
    paint_prec_recall_graph(precision_lst, recall_lst)
    dump_precision_recall(precision_lst, recall_lst, updates + 1)
    return


find_intrusion()
