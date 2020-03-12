import pyshark
from PacketPerTime import PacketPerTime
from Brain import Brain
import Detector
from PacketsPerInterval import PacketsPerInterval
import JsonParser

"""
this script parsing a pcapng file that generate on wireShark 
it create a chunk object from each packet that wireShark generate and then insert it 
to our database
"""


packets = pyshark.FileCapture("C:\\Users\\aviram\\PycharmProjects\\WiresharkParser\\PacketsData.pcapng")

# packetsBase = ChunksBase.ChunksBase(5

# TODO: create Paser -> pyshark to Packet


def parse(packet):
    return packet


TIME = 0

current_time = 0
# per_time: current working packet per time
per_time = PacketPerTime({}, current_time)

# pet_time_interval: PacketPerInterval - last 5 PacketsPerTime
per_time_interval = PacketsPerInterval([])

# brain:  BrainObj
brain = Brain.generate_from_json(JsonParser.FILE_NAME)

# current_time = packets[0][TIME]

for packet in packets:

    # translate to our object
    packet_chunk = parse(packet)

    # OR: just use packet as it is if we are running on our data set
    # packet_chunk = packet

    if packet_chunk.time == current_time:
        per_time.add_packet(packet_chunk)
        Detector.find_new_ips([packet_chunk.sender, packet_chunk.receiver], brain.ip_set, brain.malicious_ips)
        continue

    to_update = per_time_interval.update(per_time)
    if to_update is not None:
        intrusions = brain.update(to_update)
        for intrusion in intrusions:
            intrusion.get_error()

    brain_interval = brain.get_interval(current_time, PacketsPerInterval.INTERVAL)
    Detector.detect_intrusion(brain_interval, per_time_interval, brain.ip_set, brain.malicious_ips)
    per_time = []
    current_time += 1




