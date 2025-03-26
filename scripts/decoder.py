import base64
import hashlib
import random
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from meshtastic import mesh_pb2, admin_pb2, telemetry_pb2, config_pb2

DEFAULT_CHANNEL_KEY = "AQ=="
DEFAULT_PSK_KEY = [0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59, 0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01]
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
    try:
      return data[6] + data[7] + data[4] + data[5] + data[2] + data[3] + data[0] + data[1]
    except Exception:
      return data

  def generate_aes_key(self):
    key = self.decryption_key

    aes_key_len = len(base64.b64decode(key).hex())
    if aes_key_len == 32 or aes_key_len == 64:
        print("encode: ", key.encode("ascii"))
        return base64.b64decode(key.encode("ascii"))
    else:
        raise DecrypterError(
            f"The included AES key appears to be invalid. the key length is: {aes_key_len} and is not the key length of 128 or 256 bits."
            )
  def format_hex_with_spaces(self, hex_string):
    return ' '.join(hex_string[i:i+2] for i in range(0, len(hex_string), 2))

  def xorHash(self, to_hash):
    xor_result = 0
    for b in range(len(to_hash)):
      xor_result ^= to_hash[b]
    return xor_result
  
  def get_channel(self, hash, append_byte=None):
    channels_names = [ b"ShortTurbo",b"ShortSlow",b"ShortFast",b"MediumSlow",b"MediumFast",b"LongSlow",b"LongFast",b"LongMod",b"VLongSlow"]
    tmp_key = DEFAULT_PSK_KEY
    for channel in channels_names:
      c_hashed = self.xorHash(channel)
      if append_byte is not None:
         tmp_key.append(append_byte)
      c_hashed ^= self.xorHash(tmp_key)
      if c_hashed.to_bytes(1) == hash:
          return channel
    return "Unknown"

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
    # print(f"{'='*12}Packet Info{'='*12}")
    # print(mesh_packet)
    # print(f"Packet:\n{self.format_hex_with_spaces(data)}")
    # print(f"Dest:\t {self.msb2lsb(str(mesh_packet['dest'].hex()))}")
    # print(f"Sender:\t {self.msb2lsb(str(mesh_packet['sender'].hex()))}")
    # print(f"PacketID: {self.msb2lsb(str(int(mesh_packet['packetID'].hex(), 16)))}")
    # # print(f"Flags:\t {mesh_packet['flags']}")
    # flags_bit = mesh_packet['flags'][0]
    # hop_limit = (flags_bit >> 5) & 0b111
    # want_ack = (flags_bit >> 4) & 0b1
    # via_mqtt = (flags_bit >> 3) & 0b1
    # hop_start = flags_bit & 0b111
    # print(f"Hop Limit: {hop_limit}")
    # print(f"Want ACK: {want_ack}")
    # print(f"MQTT: {via_mqtt}")
    # print(f"Hop St: {hop_start}")
    # print(f"Channel: {mesh_packet['channelHash']} {mesh_packet['channelHash'].hex()}")
    # print(f"Data:\t {mesh_packet['raw_data']}")
    return mesh_packet

  def increment_bytes(self, byte_data):
    return bytes((b + random.randint(3, 10)) % 256 for b in byte_data)

  def build_fake(self, mesh_data, aes_key):
    mesh_packet = {
      "dest":  mesh_data["dest"],
      "sender":  mesh_data["sender"],
      "packetID":  mesh_data["packetID"],
      "flags":  mesh_data["flags"],
      "channelHash":  mesh_data["channelHash"],
      "reserv":  mesh_data["reserv"],
      "raw_data":  mesh_data["raw_data"],
      "data_dec": mesh_data["data_dec"]
    }
    print("Original Data:")
    print(mesh_data)
    print(self.decrypt_packet(mesh_data, aes_key))
    print("Fake Data:")
    mesh_packet["packetID"] = self.increment_bytes(mesh_packet["packetID"])
    # Decrypted
    mesh_packet["raw_data"] = self.decrypt_packet(mesh_data, aes_key)
    print(mesh_packet)
    sender_suffix = b"7c66"
    mesh_packet["raw_data"] = mesh_packet["raw_data"].replace(b"Meshtastic", b"MeshtasPwn")
    mesh_packet["raw_data"] = mesh_packet["raw_data"].replace(b"7c50", sender_suffix)
    mesh_packet["raw_data"] = mesh_packet["raw_data"].replace(mesh_packet["sender"], sender_suffix)
    sender_mod = bytearray(mesh_packet["sender"])
    sender_mod[0] = 0x66
    mesh_packet["sender"] = bytes(sender_mod)
    print(f"Dest:\t {self.msb2lsb(str(mesh_packet['dest'].hex()))}")
    print(f"Sender:\t {self.msb2lsb(str(mesh_packet['sender'].hex()))}")
    print(f"PacketID: {self.msb2lsb(str(int(mesh_packet['packetID'].hex(), 16)))}")
    print(self.decode_protobuf(mesh_packet["raw_data"], self.msb2lsb(mesh_packet["sender"].hex()), self.msb2lsb(mesh_packet["dest"].hex())))
    # Encrypt
    mesh_packet["raw_data"] = self.decrypt_packet(mesh_packet, aes_key)
    build_packet = mesh_packet["dest"] + mesh_packet["sender"] + mesh_packet["packetID"] + mesh_packet["flags"] + mesh_packet["channelHash"] + mesh_packet["reserv"] + mesh_packet["raw_data"]
    print(mesh_packet)
    print(self.decrypt_packet(mesh_packet, aes_key))
    print(f"Fake -> {build_packet}")
    print(self.hex_to_c_bytes(build_packet.hex()))
    return mesh_packet

  def hex_to_c_bytes(self, hex_str):
    hex_str = hex_str.replace(" ", "")  # Eliminar espacios
    bytes_array = [f"0x{hex_str[i:i+2]}" for i in range(0, len(hex_str), 2)]
    formatted_bytes = ", ".join(bytes_array)
    return f"unsigned char data[] = {{\n    {formatted_bytes}\n}}; // {len(bytes_array)} bytes"
    

  def decrypt_packet(self, mesh_data, aes_key):
    # Build the nonce. This is (packetID)+(00000000)+(sender)+(00000000) for a total of 128bit
    # Even though sender is a 32 bit number, internally its used as a 64 bit number.
    # Needs to be a bytes array for AES function.
    aes_nonce = mesh_data['packetID'] + b'\x00\x00\x00\x00' + mesh_data['sender'] + b'\x00\x00\x00\x00'

    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(aes_nonce), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_output = decryptor.update(mesh_data["raw_data"]) + decryptor.finalize()
    # print(f"Decrypted Hex: {decrypted_output.hex()}")
    return decrypted_output

  def decode_protobuf(self, packet_data, sourceID, destID):
    position = mesh_pb2.Position()
    print(packet_data)
    data = mesh_pb2.Data()
    admin = admin_pb2.AdminMessage()
    telem = telemetry_pb2.Telemetry()
    fromRadio = mesh_pb2.FromRadio()
    try:
      data.ParseFromString(packet_data)
    except Exception as e:
      try:
        mesh = mesh_pb2.MeshPacket()
        mesh.ParseFromString(packet_data)
        data = f"Encrypted: {mesh.encrypted} MeshPacket: {mesh}"
        return data
      except Exception as e:
        pass
      try:
        info = mesh_pb2.User()
        info.ParseFromString(packet_data)
        return info
      except:
        pass
      try:
        admin = admin_pb2.AdminMessage()
        admin.ParseFromString(packet_data)
        return admin
      except:
        pass
      try:
        config = config_pb2.Config()
        config.ParseFromString(packet_data)
        return config
      except Exception:
        return "UNKNOWN APP"
  
    match data.portnum:
      case 0: # UNKNOWN APP
        data = "UNKNOWN APP To be implemented"
      case 1: # Text Message
        data = mesh_pb2.Data()
        data.ParseFromString(packet_data)
        text_payload = data.payload.decode("latin1")
        data = f"Text Message: {str(text_payload)} {len(str(text_payload))}"
      case 3 : # POSITION_APP
        try:
          print(data.portnum)
          pos = mesh_pb2.Position()
          pos.ParseFromString(data.payload)
          latitude = telem.latitude_i * 1e-7
          longitude = telem.longitude_i * 1e-7
          data="POSITION_APP " + str(sourceID) + " -> " + str(destID) + " " + str(latitude) +"," + str(longitude)
        except Exception as e:
          data = "POSITION_APP Parse Error"
      case 4 : # NODEINFO_APP
        info = mesh_pb2.User()
        try:
            info.ParseFromString(data.payload)
        except:
            print("Unknown Nodeinfo_app parse error")
        data = f"NODEINFO_APP: \n{str(info)}\n{info.public_key}\n{info.public_key.hex()}"
      case 5:
        rtng = mesh_pb2.Routing()
        rtng.ParseFromString(data.payload)
        data = f"Telemetry {str(rtng)}"
      case 67 : # TELEMETRY_APP
        env = telemetry_pb2.Telemetry()
        env.ParseFromString(data.payload)
        data = "TELEMETRY_APP " + str(env) + " " + str(env.device_metrics)
      case _:
          data = f"Not implemented Protobuf: {data.portnum}"
    return data

  def hexdump(self, data, width=16):
    hex_lines = []
    ascii_lines = []
    
    for i in range(0, len(data), width):
      chunk = data[i:i + width]
      hex_part = " ".join(f"{byte:02X}" for byte in chunk)
      ascii_part = "".join(chr(byte) if 32 <= byte <= 126 else '.' for byte in chunk)
      hex_lines.append(hex_part.ljust(width * 3))
      ascii_lines.append(ascii_part)
    
    return "\n".join(f"{h}  {a}" for h, a in zip(hex_lines, ascii_lines))
  
  def show_details(self, mesh_packet):
    print(f"\n\n{'='*50} Packet Info {'='*50}")
    print(mesh_packet)
    isEncrypted = ""
    if mesh_packet['channelHash'].hex() == '00':
      isEncrypted = 'Unencrypted'
    print(f"Dest:\t {self.msb2lsb(str(mesh_packet['dest'].hex()))}\tSender:\t {self.msb2lsb(str(mesh_packet['sender'].hex()))}\tPacketID: {self.msb2lsb(str(int(mesh_packet['packetID'].hex(), 16)))}\tChannel: 0x{mesh_packet['channelHash'].hex()} {isEncrypted}\tModem Preset: ", end="")
    
    if type(self.get_channel(mesh_packet['channelHash'])) == str:
      print(self.get_channel(mesh_packet['channelHash']))
    else:
      print(self.get_channel(mesh_packet['channelHash']).decode('latin1'))
    
    flags_bit = mesh_packet['flags'][0]
    hop_limit = (flags_bit >> 5) & 0b111
    want_ack = (flags_bit >> 4) & 0b1
    via_mqtt = (flags_bit >> 3) & 0b1
    hop_start = flags_bit & 0b111
    print(f"Flags:\t {mesh_packet['flags'].decode('latin1')}")
    print(f"╰──▶ Hop limit: {hop_limit}")
    print(f"╰──▶ Want ACK:  {want_ack}")
    print(f"╰──▶ Via MQTT:  {via_mqtt}")
    print(f"╰──▶ Hop Start: {hop_start}")
    raw_data = mesh_packet['raw_data']
    print(f"{'-'*26} RAW Payload Hexdump ({len(raw_data)}) {'-'*26}")
    print(f"{self.hexdump(raw_data)}")
    print(raw_data)
    print(raw_data[0])
    print(raw_data[1])
    print(raw_data[2])
    dec_data = mesh_packet["data_dec"]
    print(f"{'-'*26} Decrypted Payload Hexdump ({len(raw_data)}) {'-'*26}")
    print(f"{self.hexdump(dec_data)}")
    print(dec_data)
    print(dec_data[0])
    print(dec_data[1])
    print(dec_data[2])
    print(dec_data[3])
    print(dec_data[4])
    print(dec_data[5])
    print(dec_data[6])
    print(dec_data[4:-1])
    print(self.decode_protobuf(mesh_packet["data_dec"], mesh_packet["sender"], mesh_packet["dest"]))
    print()
  
  def decryptCurve25519(self, fromNode, packetNum, data):
    # const uint8_t *auth = bytes + numBytes - 12;
    print("Decrypting curve25519")
    lenData = len(data)
    auth = data[lenData - 12:]
    extrNonce = auth[8:]
    print(fromNode)
    print(packetNum)
    print(auth)
    print(len(auth))
    print(extrNonce)
    print(len(extrNonce))
    public_key = b"0bTUzRwfa73Ty7j+c4y0lpMEZW9t2Q5pEKqwKLb7ySM="
    hash_sha256 = hashlib.sha256()
    chunk_size = 16  # Tamaño del bloque

    for i in range(0, len(public_key), chunk_size):
        hash_sha256.update(public_key[i:i + chunk_size])

    hash_sha256 = hash_sha256.digest()

    nonce = bytearray(16)
    nonce[0:4] = packetNum
    nonce[4:len(fromNode)] = fromNode
    print(nonce, nonce.hex())

  
  def decrypt(self, packet):
    aes_decryption_key = self.generate_aes_key()
    # print(aes_decryption_key.hex())
    mesh_dict = self.extract_data(packet,)
    if mesh_dict:
      decrypted_packet = self.decrypt_packet(mesh_dict, aes_decryption_key)
      # print(self.decode_protobuf(decrypted_packet, self.msb2lsb(mesh_dict["sender"].hex()), self.msb2lsb(mesh_dict["dest"].hex())))

if __name__ == "__main__":
    dec = Decrypter()
    lest_message = [
      # Primary channel
      b'\xff\xff\xff\xffP\xcd]\xa4\x98j\x98qcw\x00\x005v\xd8Q\x02\x97\xfa\xb8\x9ab\x0b\xfa\xffL[\x1b\x0chr\x06\t\xf6\xb6\x03\t\xb1M\xae\xae\xd0\xc5?'.hex(),
      b'\xff\xff\xff\xffP\xcd]\xa4[\x06\xee\x85cw\x00\x00\xf3\xb9f\x8d\xe2?l\xfal\x84tY\xfc\x89\x00\xdb\xfeo*\x95\x7fnWQ\xe8'.hex(),
      b'\xff\xff\xff\xffP\xcd]\xa4[\x06\xee\x85cw\x00\x00\xf3\xb9f\x8d\xe2?l\xfal\x84tY\xfc\x89\x00\xdb\xfeo*\x95\x7fnWQ\xe8'.hex(),
      # b'\xff\xff\xff\xffP\xcd]\xa4\x99\xce\x92\xcccw\x00\x00\xda*\x933b\x07\x10_\xce\xe9+\xa7\xca\x98\xf6@.,\xa8\xf3&\xca\xcd|c\xb8\xdd\xdeb7_"\x06\xa3\xf6'.hex(),
      # b'\xff\xff\xff\xffP\xcd]\xa4\xfe\x13\xceybw\x00P\xe4\xde\xc5\x89\xeb\xac5"in\xfd@\x012\x8a\ta=U#\x85'.hex(),
      # b'\xff\xff\xff\xffP|I\xca\xebe\xe4\x88cw\x00P\xc3\x87\xad\xbcpc|8\xdd\xc2\x7f\xfc\xca>k\x93\x83]\x93\x8b\xc0\xe5\x85@\xe9\xba\xf3ndP]i\xa6"W\x00$\x9c9\xbahs$\'\'\xef\xc6\xad\x88\x00\x07\xc0N2:z\xc1\xe8\x91\x7f\xdcSc=\'\xedm\x8f$\xd14\xa6}\xb8-\x9c\xed"\x96\xa4A1e'.hex(),
      # b"\xff\xff\xff\xffP\xcd]\xa4\xf0}\xcd]cw\x00\x00n\x99\xb7\x9d1'z\xb7'\xf8\xce~\xc0\xdd`D6\xda\xac\xb3\xd8`}\xd3\x07\xcf\x0bn\xe0\xdf\x7f\xfc\xe5\xd0\xe7\x1cu\xb6;\xff\x8f\x9c\xd0\xce\xf74\xaf\x1a\xf6a\xf1gAD\xc3\xfbO\x9e\xa5L\xe0\xf4".hex(),
      # b"\xff\xff\xff\xffP\xcd]\xa4\xf0}\xcd]bw\x00Pn\x99\xb7\x9d1'z\xb7'\xf8\xce~\xc0\xdd`D6\xda\xac\xb3\xd8`}\xd3\x07\xcf\x0bn\xe0\xdf\x7f\xfc\xe5\xd0\xe7\x1cu\xb6;\xff\x8f\x9c\xd0\xce\xf74\xaf\x1a\xf6a\xf1gAD\xc3\xfbO\x9e\xa5L\xe0\xf4".hex(),
      # b"\xff\xff\xff\xffP|I\xca\xec%\xe9\xe2cw\x00P\x0c\xe3\xf9\x80\x1bd{t\xf3\x91ie\x82\xe0\x92-HWhN|d\x8a\xefB\xf3j'\x81\x92\x90".hex(),
      # b"\xff\xff\xff\xffP|I\xca\xec%\xe9\xe2bw\x00\x00\x0c\xe3\xf9\x80\x1bd{t\xf3\x91ie\x82\xe0\x92-HWhN|d\x8a\xefB\xf3j'\x81\x92\x90".hex(),
      # b'P\xcd]\xa4P|I\xca\xedM\x9f\x19Bw\x00P^\xcf|@\x00o\xd2\xb6\xc6\xcd\xc3\x91k'.hex(),
      # Direct message
      # b'P|I\xcaP\xcd]\xa4E\xfc\x05\xe4k\x00\x00\x00\xa9\xd7 \xe2y-c\x02\xed\xf9\xd3\x06\xdd\xc7\xecG\x19\xa2~\xbdf\xa2\xfdk\xfaq\xdcz\xcf\x8c\xb1@'.hex(),
      # b'P\xcd]\xa4P|I\xca\xffu\x08\xefBw\x00P\xc2C\x89\x85\xa8\x16\x94\x0f\x06koj!'.hex(),
      # b'P|I\xcaP\xcd]\xa4E%Q\xddk\x00\x00\x00\x83\xc1\x957[\x02b\xa3~\xa0\x89\x8e\xd7\xe7\x99\xf1~\xe97\xe6\x0f\x13\xd6\xf7\x8de\xe9|\x82\xb8\x13v\xd6\x990\x83\x06F\xf6\xb5K'.hex(),
      # b'P\xcd]\xa4P|I\xca\x006\x8b\x0eBw\x00P\x8c\x06\xa3t\x07\xc5Y\x9e\xf2=|t\xc8'.hex(),
      # b'P\xcd]\xa4P|I\xca\x08YR\x12k\x00\x00P\xfa\x91\xae\x80\x08/\xa9\xfbG\x1bN\xf9\x16O}\xd0A\xc6q-\xf4QX'.hex(),
      # b'P|I\xcaP\xcd]\xa4\xd7Z\\;Bw\x00\x00\x00\x93)\xf7+W\x87\xc5~\x82\xbf]\x80'.hex(),
      # Diff hash
      # b'\xff\xff\xff\xffP\xcd]\xa4\x18\x9f\x12\xebc\x08\x00\x00|$\xf6o\xe8vV\xddL\xc6\x8f'.hex(),
      # b'\xff\xff\xff\xffP\xcd]\xa4\x18\x9f\x12\xebb\x08\x00P|$\xf6o\xe8vV\xddL\xc6\x8f'.hex(),
    ]
    aes_decryption_key = dec.generate_aes_key()
    # print(aes_decryption_key.hex())
    for mes in lest_message:
      mesh_dict = dec.extract_data(mes)
      # dec.decryptCurve25519(mesh_dict["sender"], mesh_dict["packetID"], mesh_dict["raw_data"])
      decrypted_packet = dec.decrypt_packet(mesh_dict, aes_decryption_key)
      # p = dec.build_fake(mesh_dict, aes_decryption_key)
      mesh_dict["data_dec"] = decrypted_packet
      dec.show_details(mesh_packet=mesh_dict)
      # print(dec.decode_protobuf(decrypted_packet, dec.msb2lsb(mesh_dict["sender"].hex()), dec.msb2lsb(mesh_dict["dest"].hex())))


