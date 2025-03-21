/* meshtastic.c
 *
 * SPDX-FileCopyrightText: © 2025 Kevin Leon <kevinleon.morales@gmail.com>
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#include <wsutil/wsgcrypt.h>
 #include <stdio.h>
 #include <stdint.h>
 #include <string.h>
 
 #define MESHTASTIC_DESTINATION_LEN 4 
 #define MESHTASTIC_SENDER_LEN 4 
 #define MESHTASTIC_PACKETID_LEN 4 
 #define DEFAULT_MESH_BASE64_KEY "1PG7OiApB1nwvP+rz05pAQ=="
 #define MESHTASTIC_CIPHER_SIZE 32
 #define MESHTASTIC_CIPHER_NONCE_SIZE 16
 #define AES_128_BLOCK_LEN 16

 #define TH_MASK 0x0FFF
 
 static uint8_t channel_key[] = {0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59, 0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01};

 static uint8_t xor_hash(const uint8_t *p, size_t len){
  uint8_t code = 0;
  for(size_t i=0; i < len; i++){
    code ^= p[i];
  }
  return code;
 }

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

 static char* get_lora_phy_config(uint8_t preset){
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

   
 int main(){
  uint8_t channel_hash = 0x77;
  printf("Testing\n");

  for(size_t i=0; i < meshtastic_Config_LoRaConfig_ModemPreset_SHORT_TURBO; i++){
    char *name = get_lora_phy_config(i);
    uint8_t h = xor_hash((const uint8_t *)name, strlen(name));
    h ^= xor_hash(channel_key, sizeof(channel_key));
    if(h == channel_hash){
      printf("Config: %s\n", name);
      break;
    }else{
      printf("Cannot decode hash\n");
    }
  }
  return 0;
 }