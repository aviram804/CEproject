import pyshark
from PacketPerTime import PacketPerTime
from Brain import Brain
import Detector
from PacketsPerInterval import PacketsPerInterval
import JsonParser
from matplotlib import pyplot as plt

"""
this script parsing a pcapng file that generate on wireShark 
it create a chunk object from each packet that wireShark generate and then insert it 
to our database
"""


# packets = pyshark.FileCapture("C:\\Users\\aviram\\PycharmProjects\\WiresharkParser\\PacketsData.pcapng")

# packetsBase = ChunksBase.ChunksBase(5

# TODO: create Paser -> pyshark to Packet


def parse(packet):
    return packet


TIME = 0


def display_intrusions(detected_intrusions, created_intrusions):
    """
    displays information graph for detected intrusions, compared to created ones
    :param detected_intrusions: List, detected intrusions, List of Intrusions objects
    :param created_intrusions: set, created intrusions
    """
    print("Detected intrusion length=", len(detected_intrusions),  " With Created intrusion length=", len(created_intrusions))
    for intrusion in detected_intrusions:
        flag = False
        for int in detected_intrusions:
            if int == intrusion:
                flag = True
                break
        # if intrusion not in detected_intrusions:
        if flag:
            print("True Positive")
            plt.scatter(intrusion.time, intrusion.amount_data * 5, color="blue")
        else:
            # False Positive
            plt.scatter(intrusion.time, intrusion.amount_data, color="red")

    print("Done First run")

    for intrusion in created_intrusions:
        flag = False
        for intr in detected_intrusions:
            if intr == intrusion:
                flag = True
                break
        if not flag:
            # True Negative
            plt.scatter(intrusion.time, intrusion.amount_data, color="yellow")

    plt.show()

# brain:  BrainObj
# brain = Brain.generate_from_json(JsonParser.FILE_NAME)
# current_time = packets[0][TIME]


MILLION = 1000000


def find_intrusion():

    current_time = 0

    # per_time: current working packet per time
    per_time = PacketPerTime({}, current_time)

    # pet_time_interval: PacketPerInterval - last 5 PacketsPerTime
    per_time_interval = PacketsPerInterval([])

    print("Start Generate Data")

    # Brain object, packets to run on.
    brain, packets, ip_intrusions = JsonParser.json_get_brain_chunks(JsonParser.write_intrusion_packet_chunk)

    print("Finish Country Map")

    print("Finish Generate Data")

    intrusions = set()

    for packet in packets:

        # translate to our object
        packet_chunk = parse(packet)

        # OR: just use packet as it is if we are running on our data set
        # packet_chunk = packet

        if packet_chunk.time == current_time:
            per_time.add_packet(packet_chunk)
            # Detector.find_new_ips([packet_chunk.sender, packet_chunk.receiver], brain.ip_set, brain.malicious_ips)
            continue

        to_update = per_time_interval.update(per_time)
        if to_update is not None:
            brain.update(to_update)

        brain_interval = brain.get_interval(current_time, PacketsPerInterval.INTERVAL)
        intrusions = intrusions.union(Detector.detect_intrusion(brain_interval, per_time_interval))
        current_time += 1
        per_time = PacketPerTime({}, current_time)

    print("Done Detecting, painting graph")

    display_intrusions(intrusions, ip_intrusions)


find_intrusion()
