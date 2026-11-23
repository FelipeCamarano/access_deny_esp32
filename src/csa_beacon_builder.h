#pragma once
#include <Arduino.h>
#include <cstdint>
#include <cstddef>

// Monta um beacon spoofado fingindo ser o AP alvo, com o Channel Switch
// Announcement (CSA, tag 37) dentro. O CSA diz "troquei de canal, me sigam",
// e os clientes que honram CSA pulam pro canal novo (morto) e caem.
//
// Por que fura o PMF: beacon NUNCA e protegido por 802.11w, nem em WPA3. O PMF
// so protege deauth/disassoc/action robustas. Entao esse ataque passa onde o
// deauth nao passa. (Efetividade varia por cliente: nem todo mundo honra CSA.)
class CsaBeaconBuilder {
public:
  // Escreve o beacon em out (precisa de ~128 bytes). Devolve o tamanho usado,
  // ou 0 se nao coube. switchMode fica fixo em 1 (cliente para de transmitir
  // ate a troca), o que torna o efeito mais forte.
  static size_t build(const uint8_t bssid[6], const String &ssid,
                      uint8_t currentChannel, uint8_t newChannel,
                      uint8_t switchCount, uint8_t *out, size_t outCap);
};
