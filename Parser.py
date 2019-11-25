import pyshark
from Chunks import Chunk
import ChunksBase

"""
this script parsing a pcapng file that generate on wireShark 
it create a chunk object from each packet that wireShark generate and then insert it 
to our database
"""


packets = pyshark.FileCapture("C:\\Users\\aviram\\PycharmProjects\\WiresharkParser\\PacketsData.pcapng")

packetsBase = ChunksBase.ChunksBase()

for packet in packets:
    try:
        packetsBase.add(Chunk(packet.captured_length, packet.ip.addr, packet.ip.dst, packet.frame_info.time))
        print(packet.ip.addr)
    except:
        print("no src")



