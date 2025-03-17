import base64
import binascii
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from meshtastic import mesh_pb2

DEFAULT_CHANNEL_KEY = "AQ=="
DEFAULT_MESH_BASE64_KEY = "1PG7OiApB1nwvP+rz05pAQ=="#"AAAAAAAAAAAAAAAAAAAAAA=="

MESH_PAYLOAD_PACKET = b"\xff\xff\xff\xffP|I\xca\\g\x1a~cw\x00P2\xd4\xaa\x06\xa4\xbca=\xce\x8b\xbbJ\xdb\xdc\xedJ\xd9\x84\xff\\Mj\x88\xee\xe8\xee1\x85Q\xb6X\x9c\xbc]\xf6\x04\xae\xac\x00\xb7\x9c\xe2\xe5\xf4\xcf\xca]\x8bI\x10y\xe5\xe7\x9aQ\xbe[\x1e\xf9M\xbf]\x19\x90\xa2\xbe\xd6?\x97\x83\xe1\xd9\xba\xb2'\xb98;\x87\x99\xc1\xac)s\x86"#b"\xff\xff\xff\xffP\xcd]\xa4e5\x19\xcecw\x00\x00v\xbc\xaa:\xcd\x18nq$A\x1e0`\xaf\xa0"


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
    print(f"Channel: {mesh_packet['channelHash']}")
    print(f"Data:\t {mesh_packet['raw_data']}")
    print(f"{'='*12}Packet Info{'='*12}")
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
    data = mesh_pb2.Data()
    try:
        data.ParseFromString(packet_data)
    except Exception as e:
      print(e)
      data = "INVALID PROTOBUF"
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
      case 5:
        rtng = mesh_pb2.Routing()
        rtng.ParseFromString(data.payload)
        data = f"Telemetry {str(rtng)}"
      case _:
          data = f"Not implemented Protobuf: {data.portnum}"
    return data
  
  def decrypt(self, packet):
    aes_decryption_key = self.generate_aes_key()
    mesh_dict = self.extract_data(packet)
    decrypted_packet = self.decrypt_packet(mesh_dict, aes_decryption_key)
    print(self.decode_protobuf(decrypted_packet, self.msb2lsb(mesh_dict["sender"].hex()), self.msb2lsb(mesh_dict["dest"].hex())))

if __name__ == "__main__":
    dec = Decrypter()
    lest_message = [
       b"\xff\xff\xff\xffP|I\xcao\xdf[\xcacw\x00Pr'@\xa99\x0fR\xef\x83\xaf\xfc.\xca\x94\x95\xba$d\xa3\xe5U\x88\xbf\xc6\x17\xc9\xdb\x9b\x85\xf3\xe5sK".hex(),
       b"\xff\xff\xff\xffP|I\xca^o\xfa\xf2cw\x00Pj \xa3\x9dm\xf7\xae\x0f\xc2cC\x86/L\x96^Q4R\xff\xcesG-\x8eY\xbfw\xf7\xd3\x8b<".hex(),
       b"\xff\xff\xff\xffP|I\xca:\x17&\x02cw\x00P\xb8\xfe\xbd${\x82\xf1O\xd9\x9d\x97\xd3\x051Q\xe9l\xf7`'\xcf\xa3h\x7f\xcd\xcdOC(\xf5f\xd7e\xf7".hex(),
       b"\xff\xff\xff\xffP|I\xca\\g\x1a~cw\x00P2\xd4\xaa\x06\xa4\xbca=\xce\x8b\xbbJ\xdb\xdc\xedJ\xd9\x84\xff\\Mj\x88\xee\xe8\xee1\x85Q\xb6X\x9c\xbc]\xf6\x04\xae\xac\x00\xb7\x9c\xe2\xe5\xf4\xcf\xca]\x8bI\x10y\xe5\xe7\x9aQ\xbe[\x1e\xf9M\xbf]\x19\x90\xa2\xbe\xd6?\x97\x83\xe1\xd9\xba\xb2'\xb98;\x87\x99\xc1\xac)s\x86".hex()
    ]
    aes_decryption_key = dec.generate_aes_key()
    for mes in lest_message:
      mesh_dict = dec.extract_data(mes)
      decrypted_packet = dec.decrypt_packet(mesh_dict, aes_decryption_key)
      print(dec.decode_protobuf(decrypted_packet, dec.msb2lsb(mesh_dict["sender"].hex()), dec.msb2lsb(mesh_dict["dest"].hex())))


