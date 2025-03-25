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
    print(len(mesh_packet["packetID"]))
    print(f"Packet:\n{self.format_hex_with_spaces(data)}")
    print(f"Dest:\t {self.msb2lsb(str(mesh_packet['dest'].hex()))}")
    print(f"Sender:\t {self.msb2lsb(str(mesh_packet['sender'].hex()))}")
    print(f"PacketID: {self.msb2lsb(str(int(mesh_packet['packetID'].hex(), 16)))}")
    # print(f"Flags:\t {mesh_packet['flags']}")
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
    print(aes_nonce.hex())
    print(mesh_data['packetID'])
    print(mesh_data['packetID'].hex())
    print(mesh_data['sender'])
    print(mesh_data['sender'].hex())

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
      # b'\xff\xff\xff\xffP|I\xca\x08p7\x1dcw\x00P\xd3f\xbf\x82fBC\xbf\x9c\x1d'.hex(),
      # b'\xff\xff\xff\xffP|I\xca\x08p7\x1dbw\x00\x00\xd3f\xbf\x82fBC\xbf\x9c\x1d'.hex(),
      # b'P|I\xcaP\xcd]\xa4\x0f\xeb\xab=cw\x00\x00\x07a\xbd\xfc\xc4JeBt\x00\x7f7\x1a\xc0\xfa\xbcx`\x10\xc7 "\xb5\x18\xe9\xfd\x94/"\x9f\x8c\x89-_\x98V\xb0\x9a\x98]7\xc7\xd6\xf5\xc6\x12T\x0c\x01\xc0\x8dd\x95>\xc0q73/\'\x15\xaeLr\xed\x97\x9ek\x85s\x8d\xbe\x85,7\x8d\x89\x91\xa1Z\xce\x8b\xcas`e'.hex(),
      # Fake packet
      # b'P\xcd]\xa4P|I\xca\x0c\xc7\xa5\xb2Bw\x00P\x03\x9a\xb0rB\xf8\xb4\xf3\x8faw\xe8\\>\xea]\x08\x024\x196t\x91\x82\xa8\xa6^\xb3\x01"3\xd9\xb7s\xe0\xd3*S\xb9k\x1a\xf1\xa9d\xc4\xee\xee\x80>\x1b\xf7 \t\xc5\x05\x19\xb7\xa9\xff\xaa\xffS\xcby:~8-\x9d\x88<\xd3\xb5\x95\xfcF\x96\x98\x92Z\x986w\x05\xaaD\xe9\xc0~'.hex(),
      # b'P\xcd]\xa4P|I\xca\x0c\xc7\xa5\xb2Bw\x00P\x03\x9a\xb0rB\xf8\xb4\xf3\x8faw\xe8\\>\xea]\x08\x024\x196t\x91\x82\xa8\xa6^\xb3\x01"3\xd9\xb7s\xe0\xd3*S\xb9k\x1a\xf1\xa9d\xc4\xee\xee\x80>\x1b\xf7 \t\xc5\x05\x19\xb7\xa9\xff\xaa\xffS\xcby:~8-\x9d\x88<\xd3\xb5\x95\xfcF\x96\x98\x92Z\x986w\x05\xaaD\xe9\xc0~'.hex(),
      # b'P\xcd]\xa4P|I\xca\r\xc8\xa6\xb3Bw\x00P\xf5\x19+\x93$S\x187\x8e7\x8f;\xe2\xe9\x1d\xbf\xb7\xc5\x88\xcci9\xe7\xf1\xf2A\x1c\xaeT\xc4Y\x95\xd51<\x05w\xab\x01n18P\x1a8\x0e\x92)\x0c\xca\xeet\x1b\xbcP2/\x0fQ:\xad#\x85\x86X\xb3\xe5r\xf3\xef~1\xf1\xfa\xb2\xa4\xc5\xcaT\x8e~\xae<\x02\n@A\xc3\xd2'.hex(),
      # Sniffed
      # b"\xff\xff\xff\xffP|I\xca\xc0\xb6\x9e'bw\x00\x00\xce[Vu\xea\x83\xdb\x1e\x9f\x19".hex(),
      # b'\xff\xff\xff\xffP\x8cI\xca\x08p7\x1dbw\x00\x00\xd3f\xbf\x82fBC\xbf\x9c\x1d'.hex(),
      # b'\xff\xff\xff\xffP\x8cI\xca\x08p7\x1daw\x00\x00\xd3f\xbf\x82fBC\xbf\x9c\x1d'.hex(),
      # b'P\xcd]\xa4f|I\xca\x10\xcf\xab\xbcBw\x00P{\xach\xb2)B\x1d\x1c\x8d;\xcb\xf4\x80\xfa\x0cD&M\xe4\x90\x86w>\t\x9c>\xd1\x83p\xf6\x1fL\x98\x17\xa4!Nf\x83\xe7\x11k\xb2\x02\xfaf\xac\x07\x19\x02\xd9F\x98\xaa\x95H\x13\x82\t\xdf\xfc\x96\xc6[\x126\x14\x1bK\xcf\xf5\xb2\x1d\xbf\xcb\xd1eE\xd0\xc3\xad\x02\xa7\xd8\xddj\xacb'.hex(),
      # b'P\xcd]\xa4f|I\xca\x10\xcf\xab\xbcAw\x00P{\xach\xb2)B\x1d\x1c\x8d;\xcb\xf4\x80\xfa\x0cD&M\xe4\x90\x86w>\t\x9c>\xd1\x83p\xf6\x1fL\x98\x17\xa4!Nf\x83\xe7\x11k\xb2\x02\xfaf\xac\x07\x19\x02\xd9F\x98\xaa\x95H\x13\x82\t\xdf\xfc\x96\xc6[\x126\x14\x1bK\xcf\xf5\xb2\x1d\xbf\xcb\xd1eE\xd0\xc3\xad\x02\xa7\xd8\xddj\xacb'.hex(),
      # b'\xff\xff\xff\xffP\xcd]\xa4\x12\x8f\x94\xc5c\xe0\x00\x00^\x99 2F\xb0\xad\xae\xc3\x86\xe2\t\xe5\xe3\x0b\x1eM\x9e|\xad=\x99\x18\x90\xbd\x1f>\x82D6\xbb\xe22\xbe\x08'.hex(),
      # b"\xff\xff\xff\xffP|I\xca\x8e\x14'c\xe0\x00P\x1eN0N\xc2<\x96~\x94\xac".hex(),
      # b"\xff\xff\xff\xffP|I\xca\x8e\x14'b\xe0\x00\x00\x1eN0N\xc2<\x96~\x94\xac".hex(),
      # b'P|I\xcaP\xcd]\xa4\x15;\x8e\x0bc\xe0\x00\x00\x84\x9b\xfa\xf8H\x86L<}\x8c\x01\xf6?e\xc4&\x90\xc7\x98\xac\xb1\xd7\xdc3\xa2Q\xcb\x1fIJ^\xfd\xf7\xaa\x05\x8ee-\x84\xfc\xb7\x92\x13\xc9\xf6_\xf6\x03\xce|\x97\x03\x83/\xa3\x87\xe0\xe6\xfc\x15\x9bZI<\x90\xd5\x93K\xfa\x00\xdf\x060\x7f\xab\x9c\xfb\xa5\x9f\x85\x18\x90\xaeKG\xb9'.hex(),
      # b"P\xcd]\xa4P|I\xca\xf5BH\xb8B\xe0\x00PX8\x8a,\xd9\xb6\x01\xe2u\x7f\x9dh|\x8f\x03\x02\xed\x8eh=\xd3?\xa9\x8f\xc9n7h\xfa\x02\xa6c\x17\xa7\x15\xfe\x7f\xda!\xc6Y\xe6'0_`\x9c\x1d*\x16#\x90\xae\x0b\x01\xe1\x8bg1\xc9\xa7\x87\xadE\xe2\x8a\xd6,9\xaen\x06z[)\xd4\xc6S\xf6\xab\xb9}\x1d\xa2Aq\xae\xb8".hex(),
      # b'P\xcd]\xa4P|I\xca\x91}+\xd0cw\x00Pv N}\xa3|Dw:f~\xf2\xac@\xa3[\x04\x03\x90a\x90\xf1M\x91\x98z98\x17\xbb{\xd5r\x19\x01~\xf0\x8f\xbd\xe9\xf4@\x05\x12\x89!:\xb4\x19(\x06\xeb]\xf1\xc8\t\xf0\xfc\xa7^f\xe5\x17|\xa3\x8b\xb7\xfd\xff\x10\xc4uP\xceE^M\xdf\xc5E\xa3\x8c~h\xdc'.hex(),
      # b'\xff\xff\xff\xffP\xcd]\xa4\x829\xb9\xd9cw\x00\x00\xdaD\xcc\x0f\xff\xbc&\xe4F\xea\x1c\xb5A\xa0Z\xb3\xb0\xaf\xc0<\x8d\xce\x00\xbe|\xbe\x98<\xb0\xaf\x18]'.hex(),
      # b'\xff\xff\xff\xffP\xcd]\xa4\x829\xb9\xd9bw\x00P\xdaD\xcc\x0f\xff\xbc&\xe4F\xea\x1c\xb5A\xa0Z\xb3\xb0\xaf\xc0<\x8d\xce\x00\xbe|\xbe\x98<\xb0\xaf\x18]'.hex(),
      "ffffffff50cd5da48411575c63770000c535d8db9b3273983299d7097104aea655",
    ]
    aes_decryption_key = dec.generate_aes_key()
    # print(aes_decryption_key.hex())
    for mes in lest_message:
      mesh_dict = dec.extract_data(mes)
      # dec.decryptCurve25519(mesh_dict["sender"], mesh_dict["packetID"], mesh_dict["raw_data"])
      decrypted_packet = dec.decrypt_packet(mesh_dict, aes_decryption_key)
      # p = dec.build_fake(mesh_dict, aes_decryption_key)
      # mesh_dict["data_dec"] = decrypted_packet
      # dec.show_details(mesh_packet=mesh_dict)
      # print(dec.decode_protobuf(decrypted_packet, dec.msb2lsb(mesh_dict["sender"].hex()), dec.msb2lsb(mesh_dict["dest"].hex())))


