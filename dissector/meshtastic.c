/* meshtastic.c
 *
 * SPDX-FileCopyrightText: © 2025 Kevin Leon <kevinleon.morales@gmail.com>
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This dissector is for the LoRa Phy layer
 * V0.0.1
 */

 #include <epan/capture_dissectors.h>
 #include <epan/decode_as.h>
 #include <epan/expert.h>
 #include <epan/packet.h>
 #include <epan/proto_data.h>
 #include <epan/tfs.h>
 #include <epan/to_str.h>
 #include <epan/uat.h>
 #include <gcrypt.h>
 #include <wireshark.h>
 #include <wiretap/wtap.h>
 #include <wsutil/wsgcrypt.h>
 
 #define MESHTASTIC_DESTINATION_LEN 4
 #define MESHTASTIC_SENDER_LEN 4
 #define MESHTASTIC_PACKETID_LEN 4
 #define DEFAULT_MESH_BASE64_KEY "1PG7OiApB1nwvP+rz05pAQ=="
 #define MESHTASTIC_CIPHER_SIZE 32
 #define MESHTASTIC_CIPHER_NONCE_SIZE 16
 #define AES_128_BLOCK_LEN 16
 
 #define TH_MASK 0x0FFF
 const char* decryption_key = "1PG7OiApB1nwvP+rz05pAQ==";
 static const uint8_t eventpsk[] = {
     0x38, 0x4b, 0xbc, 0xc0, 0x1d, 0xc0, 0x22, 0xd1, 0x81, 0xbf, 0x36,
     0xb8, 0x61, 0x21, 0xe1, 0xfb, 0x96, 0xb7, 0x2e, 0x55, 0xbf, 0x74,
     0x22, 0x7e, 0x9d, 0x6a, 0xfb, 0x48, 0xd6, 0x4c, 0xb1, 0xa1};
 static const uint8_t psk_key[] = {0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29,
                                   0x07, 0x59, 0xf0, 0xbc, 0xff, 0xab,
                                   0xcf, 0x4e, 0x69, 0x01};
 // Dissector handler
 static dissector_handle_t handler_meshtastic;
 // Portocol handler
 static int proto_meshtastic;
 // Header field handlers
 static int hf_meshtastic_destination;
 static int hf_meshtastic_sender;
 static int hf_meshtastic_packetid;
 static int hf_meshtastic_flags;
 static int hf_meshtastic_channelhash;
 static int hf_meshtastic_channelhash_str;
 static int hf_meshtastic_nexthop;
 static int hf_meshtastic_relaynode;
 static int hf_meshtastic_payload;
 static int hf_meshtastic_decrypted_payload;
 // Flag values
 static int hf_meshtastic_flags_hop_limit;
 static int hf_meshtastic_flags_want_ack;
 static int hf_meshtastic_flags_via_mqtt;
 static int hf_meshtastic_flags_hop_start;
 // Decrypted values
 static int hf_meshtastic_decrypted_from;
 static int hf_meshtastic_decrypted_to;
 static int hf_meshtastic_decrypted_channel;
 static int hf_meshtastic_decrypted_portnum;
 static int hf_meshtastic_decrypted_payload_len;
 // Layer 1 - Meshtastic
 // Subtree pointers
 static int ett_meshtastic;
 static int ett_flags;
 static int ett_channel;
 static int ett_packet_decrypted;
 
 typedef struct {
   guint32 destination;
   guint32 sender;
   guint32 packetid;
   uint8_t flags;
 } meshtastic_packet_t;
 
 /**
  * Create a XOR hash for the meshtastic
  *
  * @param  p       pointer to buffer, where to xor
  * @param  len     size of the buffer
  * @return xor hash
  */
 static uint8_t xor_hash(const uint8_t* p, size_t len) {
   uint8_t code = 0;
   for (size_t i = 0; i < len; i++) {
     code ^= p[i];
   }
   return code;
 }
 
 static const value_string meshtastic_portnum_list[] = {
     {0, "UNKNOWN APP"},
     {1, "Text Message"},
     {2, "Remote Hardware"},
     {3, "Position"},
     {4, "NODE Info"},
     {5, "Routing"},
     {6, "Admin"},
     {7, "Text Message Compressed"},
     {8, "Waypoint"},
     {9, "Audio"},
     {10, "Detection Sensor"},
     {32, "Reply"},
     {33, "IP Tunnel"},
     {34, "PAXCOUNTER"},
     {64, "Serial"},
     {65, "Store Forward"},
     {66, "Range Test"},
     {67, "Telemetry"},
     {68, "ZPS"},
     {69, "Simulator"},
     {70, "Traceroute"},
     {71, "Neighbord Info"},
     {72, "ATAK"},
     {73, "MAP Report"},
     {74, "POWER STRESS"},
     {256, "PRIVATE"},
     {257, "ATAK Forwarder"},
     {511, "MAX"},
 };
 
 typedef enum _meshtastic_Config_LoRaConfig_ModemPreset {
   /* Long Range - Fast */
   meshtastic_Config_LoRaConfig_ModemPreset_LONG_FAST = 0,
   /* Long Range - Slow */
   meshtastic_Config_LoRaConfig_ModemPreset_LONG_SLOW = 1,
   /* Very Long Range - Slow
 Deprecated in 2.5: Works only with txco and is unusably slow */
   meshtastic_Config_LoRaConfig_ModemPreset_VERY_LONG_SLOW = 2,
   /* Medium Range - Slow */
   meshtastic_Config_LoRaConfig_ModemPreset_MEDIUM_SLOW = 3,
   /* Medium Range - Fast */
   meshtastic_Config_LoRaConfig_ModemPreset_MEDIUM_FAST = 4,
   /* Short Range - Slow */
   meshtastic_Config_LoRaConfig_ModemPreset_SHORT_SLOW = 5,
   /* Short Range - Fast */
   meshtastic_Config_LoRaConfig_ModemPreset_SHORT_FAST = 6,
   /* Long Range - Moderately Fast */
   meshtastic_Config_LoRaConfig_ModemPreset_LONG_MODERATE = 7,
   /* Short Range - Turbo
 This is the fastest preset and the only one with 500kHz bandwidth.
 It is not legal to use in all regions due to this wider bandwidth. */
   meshtastic_Config_LoRaConfig_ModemPreset_SHORT_TURBO = 8
 } meshtastic_Config_LoRaConfig_ModemPreset;
 
 static char* get_lora_phy_config(uint8_t preset) {
   switch (preset) {
     case meshtastic_Config_LoRaConfig_ModemPreset_SHORT_TURBO:
       return "ShortTurbo";
       break;
     case meshtastic_Config_LoRaConfig_ModemPreset_SHORT_SLOW:
       return "ShortSlow";
       break;
     case meshtastic_Config_LoRaConfig_ModemPreset_SHORT_FAST:
       return "ShortFast";
       break;
     case meshtastic_Config_LoRaConfig_ModemPreset_MEDIUM_SLOW:
       return "MediumSlow";
       break;
     case meshtastic_Config_LoRaConfig_ModemPreset_MEDIUM_FAST:
       return "MediumFast";
       break;
     case meshtastic_Config_LoRaConfig_ModemPreset_LONG_SLOW:
       return "LongSlow";
       break;
     case meshtastic_Config_LoRaConfig_ModemPreset_LONG_FAST:
       return "LongFast";
       break;
     case meshtastic_Config_LoRaConfig_ModemPreset_LONG_MODERATE:
       return "LongMod";
       break;
     case meshtastic_Config_LoRaConfig_ModemPreset_VERY_LONG_SLOW:
       return "VLongSlow";
       break;
     default:
       return "Custom";
       break;
   }
 }
 
 static int dissect_meshtastic(tvbuff_t* tvb,
                               packet_info* pinfo,
                               proto_tree* tree,
                               void* data) {
   int32_t current_offset = 0;
   char* src_add_str;
   char* dst_add_str;
 
   guint32 src_addr;
   guint32 dst_addr;
   guint32 packetid;
 
   col_set_str(pinfo->cinfo, COL_PROTOCOL, "Meshtastic");
   col_clear(pinfo->cinfo, COL_INFO);
   col_clear(pinfo->cinfo, COL_DEF_DST);
   col_clear(pinfo->cinfo, COL_DEF_SRC);
 
   proto_item* ti =
       proto_tree_add_item(tree, proto_meshtastic, tvb, 0, -1, ENC_NA);
   // Radio Information
   proto_tree* ti_layer_radio = proto_item_add_subtree(ti, ett_meshtastic);
 
   // To show as little Indian
   dst_addr = GUINT32_SWAP_LE_BE(tvb_get_ntohl(tvb, current_offset));
   // Temp meanwhile I solve how to get the little indian version of the value as
   // string
   dst_add_str = tvb_bytes_to_str(pinfo->pool, tvb, current_offset,
                                  MESHTASTIC_DESTINATION_LEN);
   col_set_str(pinfo->cinfo, COL_DEF_DST, dst_add_str);
   proto_tree_add_uint(ti_layer_radio, hf_meshtastic_destination, tvb,
                       current_offset, MESHTASTIC_DESTINATION_LEN, dst_addr);
   current_offset += MESHTASTIC_DESTINATION_LEN;
 
   src_addr = GUINT32_SWAP_LE_BE(tvb_get_ntohl(tvb, current_offset));
   src_add_str =
       tvb_bytes_to_str(pinfo->pool, tvb, current_offset, MESHTASTIC_SENDER_LEN);
   col_set_str(pinfo->cinfo, COL_DEF_SRC, src_add_str);
   uint32_t sender_nonce = tvb_get_ntohl(tvb, current_offset);
   proto_tree_add_uint(ti_layer_radio, hf_meshtastic_sender, tvb, current_offset,
                       MESHTASTIC_SENDER_LEN, src_addr);
   current_offset += MESHTASTIC_SENDER_LEN;
 
   packetid = GUINT32_SWAP_LE_BE(tvb_get_ntohl(tvb, current_offset));
   uint32_t packetid_nonce = tvb_get_ntohl(tvb, current_offset);
   proto_tree_add_uint(ti_layer_radio, hf_meshtastic_packetid, tvb,
                       current_offset, MESHTASTIC_PACKETID_LEN, packetid);
   current_offset += MESHTASTIC_PACKETID_LEN;
 
   uint8_t flags_value = tvb_get_uint8(tvb, current_offset);
   proto_item* tf = proto_tree_add_uint_format(
       ti_layer_radio, hf_meshtastic_flags, tvb, current_offset, 1, flags_value,
       "Flags: 0x%02x", flags_value);
   proto_tree* field_tree = proto_item_add_subtree(tf, ett_flags);
   proto_tree_add_uint(field_tree, hf_meshtastic_flags_hop_limit, tvb,
                       current_offset, 1, flags_value & 0b111);
   proto_tree_add_boolean(field_tree, hf_meshtastic_flags_want_ack, tvb,
                          current_offset, 1, (flags_value >> 3) & 0b1);
   proto_tree_add_boolean(field_tree, hf_meshtastic_flags_via_mqtt, tvb,
                          current_offset, 1, (flags_value >> 4) & 0b1);
   proto_tree_add_uint(field_tree, hf_meshtastic_flags_hop_start, tvb,
                       current_offset, 1, (flags_value >> 5) & 0b111);
   current_offset += 1;
 
   proto_item* pi_channel =
       proto_tree_add_item(ti_layer_radio, hf_meshtastic_channelhash, tvb,
                           current_offset, 1, ENC_NA);
   proto_tree* channel_tree = proto_item_add_subtree(pi_channel, ett_channel);
   uint8_t channel_hash = tvb_get_uint8(tvb, current_offset);
 
   char* name;
 
   for (size_t i = 0; i < meshtastic_Config_LoRaConfig_ModemPreset_SHORT_TURBO;
        i++) {
     name = get_lora_phy_config(i);
     uint8_t h = xor_hash((const uint8_t*)name, strlen(name));
     h ^= xor_hash(psk_key, sizeof(psk_key));
     if (h == channel_hash) {
       break;
     } else {
       name = get_lora_phy_config(9);
     }
   }
   proto_item* pi_channel_str =
       proto_tree_add_string(channel_tree, hf_meshtastic_channelhash_str, tvb,
                             current_offset, 1, name);
   proto_item_set_generated(pi_channel_str);
   current_offset += 1;
 
   proto_tree_add_item(ti_layer_radio, hf_meshtastic_nexthop, tvb,
                       current_offset, 1, ENC_NA);
   current_offset += 1;
 
   proto_tree_add_item(ti_layer_radio, hf_meshtastic_relaynode, tvb,
                       current_offset, 1, ENC_NA);
   current_offset += 1;
 
   uint16_t payload_len = tvb_captured_length_remaining(tvb, current_offset);
   proto_item* pi_packet =
       proto_tree_add_item(ti_layer_radio, hf_meshtastic_payload, tvb,
                           current_offset, payload_len, ENC_NA);
 
   int ciphertext_captured_len;
 
   int ciphertext_reported_len =
       tvb_reported_length_remaining(tvb, current_offset);
   if (ciphertext_reported_len == 0) {
     // Error the length are too small
     col_set_str(pinfo->cinfo, COL_INFO, "[Packet length too small]");
     return tvb_captured_length(tvb);
   }
 
   // Check if the payload is truncated
   if (tvb_bytes_exist(tvb, current_offset, ciphertext_reported_len)) {
     ciphertext_captured_len = ciphertext_reported_len;
   } else {
     ciphertext_captured_len =
         tvb_captured_length_remaining(tvb, current_offset);
   }
 
   /* Cipher Instance. */
   gcry_cipher_hd_t cipher_hd;
   uint8_t aes_nonce[MESHTASTIC_CIPHER_NONCE_SIZE];
   uint8_t cipher_in[AES_128_BLOCK_LEN];
   /*
    * Create the CCM* initial block for decryption.
    */
   /*
    * Create the nonce:
    * packetid + 0x00\0x00\0x00\0x00\ + sender + 0x00\0x00\0x00\0x00
    */
   memset(aes_nonce, 0x00, 16);
   memcpy(aes_nonce, &packetid_nonce, sizeof(packetid_nonce));
   memset(aes_nonce + MESHTASTIC_PACKETID_LEN, 0x00, 4);
   memcpy(aes_nonce + MESHTASTIC_PACKETID_LEN + 4, &sender_nonce,
          sizeof(sender_nonce));
   memset(aes_nonce + MESHTASTIC_PACKETID_LEN + 4 + 4, 0x00, 4);
   memset(cipher_in, 0, 16);
   /*
    * Copy of the ciphertext in heap memory
    * Decrypt the message in-place and then use the buffer as
    * the real data for the new tvb
    */
   char* text = (char*)tvb_memdup(pinfo->pool, tvb, current_offset,
                                  ciphertext_captured_len);
   if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR,
                        0)) {
     col_set_str(pinfo->cinfo, COL_INFO, "[Failed cipher open]");
     return tvb_captured_length(tvb);
   }
   /* Set the key */
   if (gcry_cipher_setkey(cipher_hd, psk_key, AES_128_BLOCK_LEN)) {
     col_set_str(pinfo->cinfo, COL_INFO, "[Failed cipher key]");
     gcry_cipher_close(cipher_hd);
     return tvb_captured_length(tvb);
   }
   /* Set the counter. */
   if (gcry_cipher_setctr(cipher_hd, aes_nonce, AES_128_BLOCK_LEN)) {
     col_set_str(pinfo->cinfo, COL_INFO, "[Failed cipher iv]");
     gcry_cipher_close(cipher_hd);
     return tvb_captured_length(tvb);
   }
   /*
    * Perform CTR-mode transformation and decrypt (this encrypt/decrypt)
    */
 
   if (gcry_cipher_decrypt(cipher_hd, text, ciphertext_captured_len, NULL, 0)) {
     col_set_str(pinfo->cinfo, COL_INFO, "[Failed cipher decrypt]");
     return tvb_captured_length(tvb);
   }
 
   tvbuff_t* payload_tvb = tvb_new_child_real_data(
       tvb, text, ciphertext_captured_len, ciphertext_reported_len);
   add_new_data_source(pinfo, payload_tvb, "Decrypted Meshtastic Packet");
   payload_tvb = tvb_new_subset_length_caplen(
       tvb, current_offset, ciphertext_captured_len, ciphertext_reported_len);
 
   proto_tree* decrypted_tree =
   proto_item_add_subtree(pi_packet, ett_packet_decrypted);
 
   uint32_t decrypted_offset = current_offset;
   
   uint32_t decrypted_from = tvb_get_ntohl(tvb, decrypted_offset);
   proto_tree_add_uint(decrypted_tree, hf_meshtastic_decrypted_from, tvb,
                       decrypted_offset, 4, decrypted_from);
   decrypted_offset += 4;  // from
   
   uint32_t decrypted_to = tvb_get_ntohl(tvb, decrypted_offset);
   proto_tree_add_uint(decrypted_tree, hf_meshtastic_decrypted_to, tvb,
                       decrypted_offset, 4, decrypted_to);
   decrypted_offset += 4;  // to
   
   proto_tree_add_item(decrypted_tree, hf_meshtastic_decrypted_channel, tvb,
                       decrypted_offset, 1, ENC_NA);
   decrypted_offset += 1;  // channel
   // Skip the know information
   decrypted_offset += 4;   // Destination
   decrypted_offset += 4;   // Sender
   decrypted_offset += 4;   // Packetid
   decrypted_offset += 1;   // Flags
   decrypted_offset += 1;   // Channel Hash
   decrypted_offset += 1;   // Hop
   decrypted_offset += 1;   // Relay
   decrypted_offset += 1;   // Relay
 
   proto_tree_add_item(decrypted_tree, hf_meshtastic_decrypted_portnum, tvb,
                       decrypted_offset, 1, ENC_NA);
   col_set_str(pinfo->cinfo, COL_INFO, val_to_str(tvb_get_int8(tvb, 1), meshtastic_portnum_list, "Unknown"));
   decrypted_offset += 1;
   decrypted_offset += 1; // IDK WIT
   // 12 IDK WTF is this
   proto_tree_add_item(decrypted_tree, hf_meshtastic_decrypted_payload_len, tvb,
                       decrypted_offset, 1, ENC_NA);
 
   return tvb_captured_length(tvb);
 }
 
 void proto_register_meshtastic(void) {
   static hf_register_info hf[] = {
       {&hf_meshtastic_destination,
        {"Destination", "meshtastic.destination", FT_UINT32, BASE_HEX, NULL, 0x0,
         "Destination Address", HFILL}},
       {&hf_meshtastic_sender,
        {"Sender", "meshtastic.sender", FT_UINT32, BASE_HEX, NULL, 0x0,
         "Sender Address", HFILL}},
       {&hf_meshtastic_packetid,
        {"Packet ID", "meshtastic.packetid", FT_UINT32, BASE_HEX, NULL, 0x0,
         NULL, HFILL}},
 
       {&hf_meshtastic_flags,
        {"Flags", "meshtastic.flags", FT_UINT8, BASE_DEC, NULL, 0x0, NULL,
         HFILL}},
       {&hf_meshtastic_flags_hop_limit,
        {"Hop Limit", "meshtastic.hop_limit", FT_UINT8, BASE_DEC, NULL, 0x7,
         "Hop Limit value", HFILL}},
       {&hf_meshtastic_flags_want_ack,
        {"Want Ack", "meshtastic.want_ack", FT_BOOLEAN, 8, TFS(&tfs_no_yes),
         0x08, "Want Ack flag", HFILL}},
       {&hf_meshtastic_flags_via_mqtt,
        {"Via MQTT", "meshtastic.via_mqtt", FT_BOOLEAN, 8, TFS(&tfs_no_yes),
         0x10, "Via MQTT flag", HFILL}},
       {&hf_meshtastic_flags_hop_start,
        {"Hop Start", "meshtastic.hop_start", FT_UINT8, BASE_DEC, NULL, 0xE0,
         "Hop Start value", HFILL}},
 
       {&hf_meshtastic_channelhash,
        {"Channel Hash", "meshtastic.channelhash", FT_UINT8, BASE_DEC_HEX, NULL,
         0x0, NULL, HFILL}},
       {&hf_meshtastic_channelhash_str,
        {"Channel Config", "meshtastic.channel_config", FT_STRING, BASE_NONE,
         NULL, 0x0, NULL, HFILL}},
       {&hf_meshtastic_nexthop,
        {"Next Hop", "meshtastic.nexthop", FT_UINT8, BASE_DEC, NULL, 0x0, NULL,
         HFILL}},
       {&hf_meshtastic_relaynode,
        {"Relay Node", "meshtastic.relaynode", FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL}},
       {&hf_meshtastic_payload,
        {"Packet", "meshtastic.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL,
         HFILL}},
       {&hf_meshtastic_decrypted_payload,
        {"Packet", "meshtastic.decrypted_payload", FT_BYTES, BASE_NONE, NULL,
         0x0, NULL, HFILL}},
   };
   static hf_register_info hf_decrypted[] = {
       {&hf_meshtastic_decrypted_from,
        {"From", "meshtastic.from", FT_UINT32, BASE_DEC, NULL, 0x0,
         "From Address", HFILL}},
       {&hf_meshtastic_decrypted_to,
        {"To", "meshtastic.to", FT_UINT32, BASE_DEC, NULL, 0x0, "To Address",
         HFILL}},
       {&hf_meshtastic_decrypted_channel,
        {"Channel", "meshtastic.channel", FT_UINT8, BASE_DEC, NULL, 0x0, "Channel", HFILL}},
       {&hf_meshtastic_decrypted_portnum,
       {"Portnum", "meshtastic.portnum", FT_UINT8, BASE_DEC,
         VALS(meshtastic_portnum_list), 0x0, NULL, HFILL}},
       {&hf_meshtastic_decrypted_payload_len,
       {"Payload length", "meshtastic.payload_len", FT_UINT8, BASE_DEC, NULL,
         0x0, NULL, HFILL}},
   };
   static int* ett[] = {
       &ett_meshtastic,
       &ett_flags,
       &ett_channel,
   };
   // Register protocol
   proto_meshtastic =
       proto_register_protocol("Meshtastic", "Meshtastic", "meshtastic");
   // Register dissectors
   handler_meshtastic =
       register_dissector("meshtastic", dissect_meshtastic, proto_meshtastic);
   // Register header fields
   proto_register_field_array(proto_meshtastic, hf, array_length(hf));
   proto_register_field_array(proto_meshtastic, hf_decrypted,
                              array_length(hf_decrypted));
   // Register subtree
   proto_register_subtree_array(ett, array_length(ett));
 }
 
 void proto_reg_handoff_meshtastic(void) {
   dissector_add_uint("wtap_encap", WTAP_ENCAP_USER1, handler_meshtastic);
 }