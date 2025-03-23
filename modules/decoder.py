import base64
import binascii
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from meshtastic import mesh_pb2, admin_pb2, telemetry_pb2, config_pb2

DEFAULT_CHANNEL_KEY = "AQ=="
DEFAULT_MESH_BASE64_KEY = "1PG7OiApB1nwvP+rz05pAQ=="#"AAAAAAAAAAAAAAAAAAAAAA=="
DEFAULT_PSK_KEY = [0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59, 0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01]

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
  
  def format_hex_with_spaces(self, hex_string):
    return ' '.join(hex_string[i:i+2] for i in range(0, len(hex_string), 2))

  def xorHash(self, to_hash):
    xor_result = 0
    for b in range(len(to_hash)):
      xor_result ^= to_hash[b]
    return xor_result
  
  def get_channel(self, hash, append_byte=None):
    channels_names = [b"ShortTurbo",b"ShortSlow",b"ShortFast",b"MediumSlow",b"MediumFast",b"LongSlow",b"LongFast",b"LongMod",b"VLongSlow"]
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
    return mesh_packet

  def decrypt_packet(self, mesh_data, aes_key):
    # Build the nonce. This is (packetID)+(00000000)+(sender)+(00000000) for a total of 128bit
    # Even though sender is a 32 bit number, internally its used as a 64 bit number.
    # Needs to be a bytes array for AES function.
    aes_nonce = mesh_data['packetID'] + b'\x00\x00\x00\x00' + mesh_data['sender'] + b'\x00\x00\x00\x00'

    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(aes_nonce), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_output = decryptor.update(mesh_data["raw_data"]) + decryptor.finalize()
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
        data = f"Text Message: {str(text_payload)}"
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
  
  def decrypt(self, packet):
    aes_decryption_key = self.generate_aes_key()
    mesh_dict = self.extract_data(packet)
    if mesh_dict:
      decrypted_packet = self.decrypt_packet(mesh_dict, aes_decryption_key)
      if decrypted_packet:
        dec_packet = bytes.fromhex(packet[:32]) + decrypted_packet
        mesh_dict["data_dec"] = decrypted_packet
        self.show_details(mesh_packet=mesh_dict)
        return dec_packet

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
    print(f"Dest:\t {self.msb2lsb(str(mesh_packet['dest'].hex()))}\tSender:\t {self.msb2lsb(str(mesh_packet['sender'].hex()))}\tPacketID: {self.msb2lsb(str(int(mesh_packet['packetID'].hex(), 16)))}\tChannel: 0x{mesh_packet['channelHash'].hex()}\tModem Preset: ", end="")
    if mesh_packet['channelHash'] == 0x0:
      print("No encryption")
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
    dec_data = mesh_packet["data_dec"]
    print(f"{'-'*26} Decrypted Payload Hexdump ({len(raw_data)}) {'-'*26}")
    print(f"{self.hexdump(dec_data)}")
    print(dec_data)
    print(self.decode_protobuf(mesh_packet["data_dec"], mesh_packet["sender"], mesh_packet["dest"]))
    print()
