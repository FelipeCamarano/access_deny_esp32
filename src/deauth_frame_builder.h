#pragma once
#include <Arduino.h>

// Monta um frame de gerenciamento 802.11 de 26 bytes que derruba um cliente:
// Deauthentication (padrao) ou Disassociation (so muda o frame control,
// efeito parecido na pratica -- algumas SDKs bloqueiam um e deixam o outro).
// Nao valida nada: quem decide o alvo e o WifiManager, que so chama build()
// com o BSSID ja travado.
class DeauthFrameBuilder {
public:
  static const uint8_t kFrameControlDeauth = 0xC0;   // type=mgmt(00), subtype=deauth(1100)
  static const uint8_t kFrameControlDisassoc = 0xA0;  // type=mgmt(00), subtype=disassoc(1010)

  static void build(const uint8_t targetMac[6], const uint8_t bssid[6],
                     uint16_t reason, uint8_t out[26],
                     uint8_t frameControl0 = kFrameControlDeauth);
};
