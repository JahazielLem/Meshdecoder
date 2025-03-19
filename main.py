import base64
import binascii
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from meshtastic import mesh_pb2, admin_pb2, telemetry_pb2

DEFAULT_CHANNEL_KEY = "AQ=="
DEFAULT_MESH_BASE64_KEY = "1PG7OiApB1nwvP+rz05pAQ=="#"AAAAAAAAAAAAAAAAAAAAAA=="

meshtastic_MeshPacket_to_tag =             2
meshtastic_MeshPacket_channel_tag =        3
meshtastic_MeshPacket_decoded_tag =        4

class DecrypterError(Exception):
    pass


class Decrypter:
  def __init__(self, aeskey=None):
    self.decryption_key = DEFAULT_MESH_BASE64_KEY
  
  def hexStringToBinary(self, hexString):
    binString = bytes.fromhex(hexString)
    return binString
  
  def msb2lsb(self, data):
    return data[6] + data[7] + data[4] + data[5] + data[2] + data[3] + data[0] + data[1]

  def generate_aes_key(self):
    key = self.decryption_key

    aes_key_len = len(base64.b64decode(key).hex())
    if aes_key_len == 32 or aes_key_len == 64:
        return base64.b64decode(key.encode("ascii"))
    else:
        raise DecrypterError(
            f"The included AES key appears to be invalid. the key length is: {aes_key_len} and is not the key length of 128 or 256 bits."
            )

  def extract_data(self, data=b""):
    # https://meshtastic.org/docsoverview/mesh-algo/#layer-1-unreliable-zero-hop-messaging
    # Meshtastic - Layer 1
    # 0x00 - 4 bytes Destionation NodeID - 0xFFFFFFFF (Broadcast)
    # 0x04 - 4 bytes Sender NodeID
    # 0x08 - 4 bytes Packer Header sending node
    # 0x0C - 1 byte Packet Header Flags
    # 0x0D - 1 byte Packet Header channel hash (hint for decryption)
    # 0x0E - 1 byte Packet Header Next-hop
    # 0x0F - 1 byte Packet Heeader relay node of the current transmission
    # 0x10 - max 237 bytes - Packet data
    mesh_packet = {
    "dest": self.hexStringToBinary(data[0:8]),
    "sender": self.hexStringToBinary(data[8:16]),
    "packetID": self.hexStringToBinary(data[16:24]),
    "flags": self.hexStringToBinary(data[24:26]),
    "channelHash": self.hexStringToBinary(data[26:28]),
    "reserv": self.hexStringToBinary(data[28:32]),
    "raw_data": self.hexStringToBinary(data[32 : len(data)]),
    "data_dec": ""
    }
    print(f"{'='*12}Packet Info{'='*12}")
    print(mesh_packet)
    print(f"Packet: {data}")
    print(f"Dest:\t {self.msb2lsb(str(mesh_packet['dest'].hex()))}")
    print(f"Sender:\t {self.msb2lsb(str(mesh_packet['sender'].hex()))}")
    print(f"PacketID: {self.msb2lsb(str(int(mesh_packet['packetID'].hex(), 16)))}")
    print(f"Flags:\t {mesh_packet['flags']}")
    flags_bit = mesh_packet['flags'][0]
    hop_limit = (flags_bit >> 5) & 0b111
    want_ack = (flags_bit >> 4) & 0b1
    via_mqtt = (flags_bit >> 3) & 0b1
    hop_start = flags_bit & 0b111
    print(f"Hop Limit: {hop_limit}")
    print(f"Want ACK: {want_ack}")
    print(f"MQTT: {via_mqtt}")
    print(f"Hop St: {hop_start}")
    print(f"Channel: {mesh_packet['channelHash']} {mesh_packet['channelHash'].hex()}")
    print(f"Data:\t {mesh_packet['raw_data']}")
    return mesh_packet

  def decrypt_packet(self, mesh_data, aes_key):
    # Build the nonce. This is (packetID)+(00000000)+(sender)+(00000000) for a total of 128bit
    # Even though sender is a 32 bit number, internally its used as a 64 bit number.
    # Needs to be a bytes array for AES function.
    aes_nonce = mesh_data['packetID'] + b'\x00\x00\x00\x00' + mesh_data['sender'] + b'\x00\x00\x00\x00'
    # print(f"AES Nonce: {aes_nonce.hex()}")
    # print(f"AES key: {str(base64.b64encode(aes_key))}")

    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(aes_nonce), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_output = decryptor.update(mesh_data["raw_data"]) + decryptor.finalize()
    # print(f"Decrypted Hex: {decrypted_output.hex()}")
    return decrypted_output

  def decode_protobuf(self, packet_data, sourceID, destID):
    position = mesh_pb2.Position()
    data = mesh_pb2.Data()
    admin = admin_pb2.AdminMessage()
    telem = telemetry_pb2.Telemetry()
    fromRadio = mesh_pb2.FromRadio()
    try:
        data.ParseFromString(packet_data)
        # position.ParseFromString(packet_data)
        # admin.ParseFromString(packet_data)
        # fromRadio.ParseFromString(packet_data)
    except Exception as e:
      print(e)
      data = "INVALID PROTOBUF"
      print("")
      return data
  
    match data.portnum:
      case 0: # UNKNOWN APP
        data = "UNKNOWN APP To be implemented"
      case 1: # Text Message
          text_payload = data.payload.decode("utf-8")
          if(destID == str("ffffffff")):
            data = f"Text Message: {str(sourceID)} -> {str(destID)} {str(text_payload)}"
          else:
             data = f"Text Message: {str(sourceID)} -> {str(destID)} Direct Message Censored"
      case 3 : # POSITION_APP
            pos = mesh_pb2.Position()
            pos.ParseFromString(data.payload)
            latitude = pos.latitude_i * 1e-7
            longitude = pos.longitude_i * 1e-7
            data="POSITION_APP " + str(sourceID) + " -> " + str(destID) + " " + str(latitude) +"," + str(longitude)
      case 5:
        rtng = mesh_pb2.Routing()
        rtng.ParseFromString(data.payload)
        data = f"Telemetry {str(rtng)}"
      case _:
          data = f"Not implemented Protobuf: {data.portnum}"
    print(f"{'='*12}Packet Info{'='*12}")
    return data
  
  def decrypt(self, packet):
    aes_decryption_key = self.generate_aes_key()
    mesh_dict = self.extract_data(packet)
    if mesh_dict:
      decrypted_packet = self.decrypt_packet(mesh_dict, aes_decryption_key)
      print(self.decode_protobuf(decrypted_packet, self.msb2lsb(mesh_dict["sender"].hex()), self.msb2lsb(mesh_dict["dest"].hex())))

if __name__ == "__main__":
    dec = Decrypter()
    lest_message = [
      b'\xff\xff\xff\xffP\xcd]\xa4\x99\x0brn\x00w\x00\x00%lE!y`.`\xc5\x1e\xdb\xefU\xa7\x0c\x12b\tf\xb0M\x05,\x1a~\xf5\xc8\x16\xa7\xd6\x13\xac|'.hex(), #Protobuf 3
      b'\xff\xff\xff\xffP\xcd]\xa4\x1cZ<Wbw\x00P(+\xaf\xb2\x07 \xd4\xf5\x06\xa3'.hex(),
      b'\xff\xff\xff\xffP\xcd]\xa4\x9b\x8b3\xd2cw\x00\x00\xc6\x0f\x15\xa1\x8e\xdaq\x82\xeaL\xac2\x98G\xc0\x03\xdeZ\xbb\xc2/\x93\x89\xe0\xe79:\xe7\xbe{\xd7\t=\xda&\xb9'.hex(),
      b'\xff\xff\xff\xffP\xcd]\xa4\x9b\x8b3\xd2bw\x00P\xc6\x0f\x15\xa1\x8e\xdaq\x82\xeaL\xac2\x98G\xc0\x03\xdeZ\xbb\xc2/\x93\x89\xe0\xe79:\xe7\xbe{\xd7\t=\xda&\xb9'.hex(),
      b'\xff\xff\xff\xffP\xcd]\xa4\x89\x1f\xb1gcw\x00\x00s\xf0b\x1a\x9fU\x9d\xe6\xba\xc4x\x9f\xd3\xe5\xac\xa6\xc0\xed\x8c\xd5\xcc<\xc6\xdcn(\x12\xb0\x86l\x15\xc7\xd4\xf6\x04~\xda\x84\x10 \xe8Id\x81@\xfd*\x90PB\x9d\xf9V\x08\xc3\xc1?3\x0e]\x81'.hex(),
      b'\xff\xff\xff\xffP\xcd]\xa4\x9d[\xddm\x00w\x00\x00N\xee~J\xe1\xf9\x82\xda\xa1lS\x8c\x7f\x84\xba=\xe8\x10\xbc\xc1\xc1P5\x1d\xb4}M\xcf\xc5\xc2\xa4\xe4E'.hex(),
      b'\xff\xff\xff\xffP\xcd]\xa4\x89\x1f\xb1gbw\x00Ps\xf0b\x1a\x9fU\x9d\xe6\xba\xc4x\x9f\xd3\xe5\xac\xa6\xc0\xed\x8c\xd5\xcc<\xc6\xdcn(\x12\xb0\x86l\x15\xc7\xd4\xf6\x04~\xda\x84\x10 \xe8Id\x81@\xfd*\x90PB\x9d\xf9V\x08\xc3\xc1?3\x0e]\x81'.hex(),
      b'P|I\xcaP\xcd]\xa4?x\x1e\x9fk\x00\x00\x00Cd\xcf\xf5\xc7\xd4?us\xad\xb7\x7fi\x15\xac<X\xdd\xd4\xb8\x12?--\xf4QX'.hex(),
      b'P\xcd]\xa4P|I\xca\t\t\x8bYBw\x00Pa\xa0Q\x81\x84/\xfe\xf8f\xac\x98\x1dV'.hex(),
      b'P|I\xcaP\xcd]\xa4\x99\x0f\x91\xa8k\x00\x00\x00\x93[\xee\xcc,\xfd{W\x96o\xd3\x11.\xd0\xe3\x8e\xd3\xa0q=\xcf\x8c\xb1@'.hex(),
      b'P\xcd]\xa4P|I\xca\xc5\x92cBw\x00P\xe0\x9c\xd9D\xdb\x81\xae\x8d\x97\x00&\xd5\x00'.hex(),
      b'P|I\xcaP\xcd]\xa4\x11\xbdDk\x00\x00\x00\x02\x15\xdbC\xc0,w\xf2:\x82\xeb\x0fxV\x9a\x82\x8d\xee`$(F\xf6\xb5K'.hex(),
      b'P\xcd]\xa4P|I\xca\x0b\x99\xa9YBw\x00P\xc2\xca\x19\xbcH\x95:s\xa9\xb7Q\xc0\xa1'.hex(),
      b'\xff\xff\xff\xffP\xcd]\xa4\x99\x0brn\x00w\x00\x00%lE!y`.`\xc5\x1e\xdb\xefU\xa7\x0c\x12b\tf\xb0M\x05,\x1a~\xf5\xc8\x16\xa7\xd6\x13\xac|'.hex(),
      b'\xff\xff\xff\xffP\xcd]\xa4\x1cZ<Wbw\x00P(+\xaf\xb2\x07 \xd4\xf5\x06\xa3'.hex(),
      b'\xff\xff\xff\xffP\xcd]\xa4\x9b\x8b3\xd2cw\x00\x00\xc6\x0f\x15\xa1\x8e\xdaq\x82\xeaL\xac2\x98G\xc0\x03\xdeZ\xbb\xc2/\x93\x89\xe0\xe79:\xe7\xbe{\xd7\t=\xda&\xb9'.hex(),
      b'\xff\xff\xff\xffP\xcd]\xa4\x9b\x8b3\xd2bw\x00P\xc6\x0f\x15\xa1\x8e\xdaq\x82\xeaL\xac2\x98G\xc0\x03\xdeZ\xbb\xc2/\x93\x89\xe0\xe79:\xe7\xbe{\xd7\t=\xda&\xb9'.hex(),
      b'\xff\xff\xff\xffP\xcd]\xa4\x89\x1f\xb1gcw\x00\x00s\xf0b\x1a\x9fU\x9d\xe6\xba\xc4x\x9f\xd3\xe5\xac\xa6\xc0\xed\x8c\xd5\xcc<\xc6\xdcn(\x12\xb0\x86l\x15\xc7\xd4\xf6\x04~\xda\x84\x10 \xe8Id\x81@\xfd*\x90PB\x9d\xf9V\x08\xc3\xc1?3\x0e]\x81'.hex(),
    ]
    aes_decryption_key = dec.generate_aes_key()
    for mes in lest_message:
      mesh_dict = dec.extract_data(mes)
      decrypted_packet = dec.decrypt_packet(mesh_dict, aes_decryption_key)
      print(dec.decode_protobuf(decrypted_packet, dec.msb2lsb(mesh_dict["sender"].hex()), dec.msb2lsb(mesh_dict["dest"].hex())))


