#include "packet_sniffer.h"
#include <cstring>
#include <cstdio>

PacketSniffer *PacketSniffer::instance_ = nullptr;

static String macToString(const uint8_t *mac) {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

// Le o primeiro information element do corpo (deveria ser o SSID). So vale pra
// frames cujo corpo comeca direto nos IEs, sem campos fixos antes -- caso do
// Probe Request, que comeca logo apos os 24 bytes do cabecalho MAC.
static String parseSsidIe(const uint8_t *frame, int len) {
  int offset = 24;
  if (offset + 2 > len) return String("");
  uint8_t tagNum = frame[offset];
  uint8_t tagLen = frame[offset + 1];
  if (tagNum != 0) return String("");  // primeiro IE nao e SSID, foge do padrao
  if (offset + 2 + tagLen > len) return String("");
  if (tagLen == 0) return String("");  // probe "coringa", sem SSID especifico
  char buf[33];
  int n = tagLen > 32 ? 32 : tagLen;
  memcpy(buf, frame + offset + 2, n);
  buf[n] = '\0';
  return String(buf);
}

// Le o RSN IE (tag 48) de um beacon pra saber se o alvo exige/suporta PMF.
// Corpo do beacon comeca em offset 24 (header) + 12 (timestamp/interval/capab).
static void parseBeaconPmf(const uint8_t *frame, int len, PmfInfo &out) {
  int offset = 24 + 12;
  while (offset + 2 <= len) {
    uint8_t tag = frame[offset];
    uint8_t tagLen = frame[offset + 1];
    int dataStart = offset + 2;
    if (dataStart + tagLen > len) return;  // IE cortado, desiste

    if (tag == 48) {  // RSN Information Element
      const uint8_t *d = frame + dataStart;
      int p = 2;  // pula "version" (2 bytes)
      if (p + 4 > tagLen) return;
      p += 4;  // group cipher suite
      if (p + 2 > tagLen) return;
      uint16_t pcount = d[p] | (d[p + 1] << 8);
      p += 2 + 4 * pcount;  // lista de pairwise cipher suites
      if (p + 2 > tagLen) return;
      uint16_t acount = d[p] | (d[p + 1] << 8);
      p += 2 + 4 * acount;  // lista de AKM suites
      if (p + 2 > tagLen) return;  // sem campo de RSN Capabilities nesse beacon
      uint16_t caps = d[p] | (d[p + 1] << 8);
      out.known = true;
      out.capable = (caps & 0x0080) != 0;   // bit7 = MFPC
      out.required = (caps & 0x0040) != 0;  // bit6 = MFPR
      return;
    }
    offset = dataStart + tagLen;
  }
}

void PacketSniffer::begin(const uint8_t bssid[6], const String &ssid, const SniffConfig &cfg) {
  memcpy(targetBssid_, bssid, 6);
  targetSsid_ = ssid;
  cfg_ = cfg;
  buffer_.clear();
  stats_ = SniffStats{};
  pmf_ = PmfInfo{};
  instance_ = this;
  // registra o callback antes de ligar o promiscuo, pra nao perder frame no meio.
  esp_wifi_set_promiscuous_rx_cb(&PacketSniffer::onPacket);
  esp_wifi_set_promiscuous(true);
}

void PacketSniffer::end() {
  esp_wifi_set_promiscuous(false);
  instance_ = nullptr;
}

void PacketSniffer::onPacket(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT || !instance_) return;
  instance_->handlePacket((const wifi_promiscuous_pkt_t *)buf);
}

void PacketSniffer::push(const SniffEntry &entry) {
  if (buffer_.size() >= kMaxEntries) {
    buffer_.erase(buffer_.begin());  // descarta o mais antigo (FIFO)
  }
  buffer_.push_back(entry);
}

void PacketSniffer::handlePacket(const wifi_promiscuous_pkt_t *pkt) {
  const uint8_t *p = pkt->payload;
  int len = pkt->rx_ctrl.sig_len;
  if (len < 24) return;

  uint8_t frameControl = p[0];
  uint8_t subtype = (frameControl >> 4) & 0x0F;
  const uint8_t *addr2 = p + 10;  // origem = MAC real (ou ja randomizado) do dispositivo
  const uint8_t *addr3 = p + 16;  // BSSID do frame

  stats_.mgmtSeen++;

  if (subtype == 0x08) {  // beacon
    stats_.beaconSeen++;
    if (!pmf_.known && memcmp(addr3, targetBssid_, 6) == 0) {
      parseBeaconPmf(p, len, pmf_);
    }
    return;
  }

  if (subtype == 0x04) {  // probe request
    stats_.probeReqSeen++;
    if (!cfg_.captureProbe) return;
    String ssid = parseSsidIe(p, len);
    bool match = targetSsid_.length() > 0 && ssid == targetSsid_;
    push(SniffEntry{"probe_req", macToString(addr2), ssid, match});
    return;
  }

  if (subtype != 0x00 && subtype != 0x02) return;  // so nos interessa assoc/reassoc daqui

  bool isReassoc = (subtype == 0x02);
  if (isReassoc) stats_.reassocReqSeen++; else stats_.assocReqSeen++;

  bool bssidMatch = memcmp(addr3, targetBssid_, 6) == 0;
  if (bssidMatch) stats_.matched++;

  bool wantIt = isReassoc ? cfg_.captureReassoc : cfg_.captureAssoc;
  if (!wantIt) return;

  push(SniffEntry{isReassoc ? "reassoc_req" : "assoc_req", macToString(addr2), "", bssidMatch});
}
