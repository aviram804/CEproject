import pyshark


"""
this script parsing a pcapng file that generate on wireShark 
it create a chunk object from each packet that wireShark generate and then insert it 
to our database
"""


packets = pyshark.FileCapture("C:\\Users\\aviram\\PycharmProjects\\WiresharkParser\\PacketsData.pcapng")

# packetsBase = ChunksBase.ChunksBase(5

for packet in packets:
    # try:
        # packetsBase.add(Chunk(packet.captured_length, packet.ip.addr, packet.ip.dst, packet.frame_info.time))



    # except:
        print("no src")


