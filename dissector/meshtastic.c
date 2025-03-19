/* meshtastic.c
 *
 * SPDX-FileCopyrightText: © 2025 Kevin Leon <kevinleon.morales@gmail.com>
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

 #include <epan/packet.h>
 #include <epan/capture_dissectors.h>
 #include <epan/decode_as.h>
 #include <epan/proto_data.h>
 #include <epan/to_str.h>
 #include <epan/tfs.h>
 #include <wireshark.h>
 #include <wiretap/wtap.h>
 #include "../../../epan/dissectors/packet-ieee802154.h" /* I use CCM implementation available as part of 802.15.4 dissector */
 
 #define MESHTASTIC_DESTINATION_LEN 4 
 #define MESHTASTIC_SENDER_LEN 4 
 #define MESHTASTIC_PACKETID_LEN 4 
 #define DEFAULT_MESH_BASE64_KEY "1PG7OiApB1nwvP+rz05pAQ=="
 #define MESHTASTIC_CIPHER_SIZE 32
 #define MESHTASTIC_CIPHER_NONCE_SIZE 16
 #define AES_128_BLOCK_LEN 16

 #define TH_MASK 0x0FFF
 
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
 static int hf_meshtastic_nexthop;
 static int hf_meshtastic_relaynode;
 static int hf_meshtastic_payload;
 // Flag values
 static int hf_meshtastic_flags_hop_limit;
 static int hf_meshtastic_flags_want_ack;
 static int hf_meshtastic_flags_via_mqtt;
 static int hf_meshtastic_flags_hop_start;
 // Layer 1 - Meshtastic
 // Subtree pointers
 static int ett_meshtastic;
 static int ett_flags;

typedef struct {
  guint32 destination;
  guint32 sender;
  guint32 packetid;
  uint8_t flags;
 } meshtastic_packet_t;

 static int dissect_meshtastic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data){
   meshtastic_packet_t packet_ctx;
   int32_t current_offset = 0;
   char *src_add_str;
   char *dst_add_str;
   
   guint32 src_addr;
   guint32 dst_addr;
   guint32 packetid;
 
   col_set_str(pinfo->cinfo, COL_PROTOCOL, "Meshtastic");
   col_clear(pinfo->cinfo, COL_INFO);
   col_clear(pinfo->cinfo, COL_DEF_DST);
   col_clear(pinfo->cinfo, COL_DEF_SRC);
 
   proto_item *ti = proto_tree_add_item(tree, proto_meshtastic, tvb, 0, -1, ENC_NA);
   // Radio Information
   proto_tree *ti_layer_radio = proto_item_add_subtree(ti, ett_meshtastic);

   dst_addr = GUINT32_SWAP_LE_BE(tvb_get_ntohl(tvb, current_offset));
   dst_add_str = tvb_bytes_to_str(pinfo->pool, tvb, current_offset, MESHTASTIC_DESTINATION_LEN);
   col_set_str(pinfo->cinfo, COL_DEF_DST, dst_add_str);
   packet_ctx.destination = dst_addr;
   proto_tree_add_uint(ti_layer_radio, hf_meshtastic_destination, tvb, current_offset, MESHTASTIC_DESTINATION_LEN, dst_addr);
   current_offset += MESHTASTIC_DESTINATION_LEN;
   
   src_addr = GUINT32_SWAP_LE_BE(tvb_get_ntohl(tvb, current_offset));
   src_add_str = tvb_bytes_to_str(pinfo->pool, tvb, current_offset, MESHTASTIC_SENDER_LEN);
   col_set_str(pinfo->cinfo, COL_DEF_SRC, src_add_str);
   packet_ctx.destination = src_addr;
   proto_tree_add_uint(ti_layer_radio, hf_meshtastic_sender, tvb, current_offset, MESHTASTIC_SENDER_LEN, src_addr);
   current_offset += MESHTASTIC_SENDER_LEN;
   
   packetid = GUINT32_SWAP_LE_BE(tvb_get_ntohl(tvb, current_offset));
   packet_ctx.packetid = packetid;
   proto_tree_add_uint(ti_layer_radio, hf_meshtastic_packetid, tvb, current_offset, MESHTASTIC_PACKETID_LEN, packetid);
   current_offset += MESHTASTIC_PACKETID_LEN;
 
   uint8_t flags_value = tvb_get_uint8(tvb, current_offset);
   packet_ctx.flags = flags_value;
   proto_item *tf = proto_tree_add_uint_format(ti_layer_radio, hf_meshtastic_flags, tvb, current_offset, 1, flags_value, "Flags: 0x%02x", flags_value);
   proto_tree *field_tree = proto_item_add_subtree(tf, ett_flags);
   proto_tree_add_uint(field_tree, hf_meshtastic_flags_hop_limit, tvb, current_offset, 1, (flags_value >> 5) & 0b111);
   proto_tree_add_boolean(field_tree, hf_meshtastic_flags_want_ack, tvb, current_offset, 1, (flags_value >> 4) & 0b1);
   proto_tree_add_boolean(field_tree, hf_meshtastic_flags_via_mqtt, tvb, current_offset, 1, (flags_value >> 3) & 0b1);
   proto_tree_add_uint(field_tree, hf_meshtastic_flags_hop_start, tvb, current_offset, 1, flags_value & 0b111);
   current_offset += 1;

   proto_tree_add_uint(ti_layer_radio, hf_meshtastic_channelhash, tvb, current_offset, 1, ENC_NA);
   current_offset += 1;
   
   proto_tree_add_uint(ti_layer_radio, hf_meshtastic_nexthop, tvb, current_offset, 1, ENC_NA);
   current_offset += 1;

   proto_tree_add_uint(ti_layer_radio, hf_meshtastic_relaynode, tvb, current_offset, 1, ENC_NA);
  //  current_offset += 1;
   
   uint16_t payload_len = tvb_captured_length_remaining(tvb, current_offset);
   proto_tree_add_item(ti_layer_radio, hf_meshtastic_payload, tvb, current_offset, payload_len, ENC_NA);

  uint8_t aes_nonce[MESHTASTIC_CIPHER_NONCE_SIZE];
  uint8_t tmp[AES_128_BLOCK_LEN];
  // uint8_t *decryption_key;
  int ciphertext_captured_len;
  
  int ciphertext_reported_len = tvb_reported_length_remaining(tvb, current_offset + payload_len);
  if(ciphertext_reported_len == 0){
    // Error the length are too small
    return 1;
  }

  // Check if the payload is truncated
  if(tvb_bytes_exist(tvb, current_offset, ciphertext_reported_len)){
    ciphertext_captured_len = ciphertext_reported_len;
  }else{
    ciphertext_captured_len = tvb_captured_length_remaining(tvb, current_offset);
  }

  memcpy(aes_nonce, &packet_ctx.packetid, MESHTASTIC_PACKETID_LEN);
  memset(aes_nonce + MESHTASTIC_PACKETID_LEN, 0x00, 4);
  memcpy(aes_nonce + MESHTASTIC_PACKETID_LEN + 4, &packet_ctx.sender, MESHTASTIC_SENDER_LEN);
  memset(aes_nonce + MESHTASTIC_PACKETID_LEN + 4 + MESHTASTIC_SENDER_LEN, 0x00, 4);

  /*
  * Create the CCM* initial block for decryption.
  */

  //  ccm_init_block(tmp, false, 0, 0, 0, 0, 0, aes_nonce);
   
   return tvb_captured_length(tvb);
 }
 
 void proto_register_meshtastic(void){
   static hf_register_info hf[] = {
     {&hf_meshtastic_destination, {"Destination", "meshtastic.destination", FT_UINT32, BASE_HEX, NULL, 0x0, "Destination Address", HFILL }},
     {&hf_meshtastic_sender, {"Sender", "meshtastic.sender", FT_UINT32, BASE_HEX, NULL, 0x0, "Sender Address", HFILL }},
     {&hf_meshtastic_packetid, {"Packet ID", "meshtastic.packetid", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
     
     {&hf_meshtastic_flags, {"Flags", "meshtastic.flags", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
     {&hf_meshtastic_flags_hop_limit, {"Hop Limit", "meshtastic.hop_limit", FT_UINT8, BASE_DEC, NULL, 0x7, "Hop Limit value", HFILL }},
     {&hf_meshtastic_flags_want_ack, {"Want Ack", "meshtastic.want_ack", FT_BOOLEAN, 8, TFS(&tfs_no_yes), 0x08, "Want Ack flag", HFILL }},
     {&hf_meshtastic_flags_via_mqtt, {"Via MQTT", "meshtastic.via_mqtt", FT_BOOLEAN, 8, TFS(&tfs_no_yes), 0x10, "Via MQTT flag", HFILL }},
     {&hf_meshtastic_flags_hop_start, {"Hop Start", "meshtastic.hop_start", FT_UINT8, BASE_DEC, NULL, 0xE0, "Hop Start value", HFILL }},
     
     {&hf_meshtastic_channelhash, {"Channel Hash", "meshtastic.channelhash", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
     {&hf_meshtastic_nexthop, {"Next Hop", "meshtastic.nexthop", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
     {&hf_meshtastic_relaynode, {"Relay Node", "meshtastic.relaynode", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
     {&hf_meshtastic_payload, {"Packet", "meshtastic.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
   };
   static int *ett[] = {
     &ett_meshtastic,
     &ett_flags,
   };
   // Register protocol
   proto_meshtastic = proto_register_protocol("Meshtastic", "Meshtastic", "meshtastic");
   // Register dissectors
   handler_meshtastic = register_dissector("meshtastic", dissect_meshtastic, proto_meshtastic);
   // Register header fields
   proto_register_field_array(proto_meshtastic, hf, array_length(hf));
   // Register subtree
   proto_register_subtree_array(ett, array_length(ett));
 }
 
 void proto_reg_handoff_meshtastic(void)
 {
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USER1, handler_meshtastic);
 }