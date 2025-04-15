import struct
import binascii
# PCAP -> LinkType
LINKTYPE_USER_DLT = 148
# PCAP
PCAP_GLOBAL_HEADER_FORMAT = "<LHHIILL"
PCAP_PACKET_HEADER_FORMAT = "<llll"
PCAP_MAGIC_NUMBER = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_MAX_PACKET_SIZE = 0x0000FFFF

def get_global_header(interface=LINKTYPE_USER_DLT):
  global_header = struct.pack(
    PCAP_GLOBAL_HEADER_FORMAT,
    PCAP_MAGIC_NUMBER,
    PCAP_VERSION_MAJOR,
    PCAP_VERSION_MINOR,
    0,  # Reserved
    0,  # Reserved
    PCAP_MAX_PACKET_SIZE,
    interface,
  )
  return global_header


class Pcap:
  def __init__(self, packet, timestamp_seconds):
    self.packet = packet
    self.timestamp_seconds = timestamp_seconds
    self.pcap_packet = self.pack()

  def pack(self):
    int_timestamp = int(self.timestamp_seconds)
    timestamp_offset = int((self.timestamp_seconds - int_timestamp) / 1_000_000)
    return (
      struct.pack(
        PCAP_PACKET_HEADER_FORMAT,  # Block Type
        int_timestamp,  # timestamp_seconds,
        timestamp_offset,  # timestamp_offset,
        len(self.packet),  # Snapshot Length
        len(self.packet),  # Packet Length
      )
      + self.packet
    )

  def hex(self):
    return binascii.hexlify(self.pcap_packet).decode("utf-8")

  def bytes(self):
    return self.pcap_packet

  def __bytes__(self):
    return self.pcap_packet
  
  def __str__(self) -> str:
    return self.pcap_packet.hex()
