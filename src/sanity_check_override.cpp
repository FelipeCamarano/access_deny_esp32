// Tentativa do Metodo 1 (override via linker) antes de continuar o patch
// binario manual. A funcao fechada da SDK (dentro de libnet80211.a) recusa
// frame de deauth/disassoc cru. Declarando a mesma assinatura aqui, com
// "extern C" (sem name mangling do C++), e deixando -Wl,-zmuldefs no
// platformio.ini permitir multipla definicao, a gente tenta fazer essa
// versao "ganhar" do linker e sempre devolver 0 (frame valido).
//
// Pode nao funcionar nessa versao do IDF (documentado que falha em builds
// mais novos, onde a chamada interna e resolvida antes do link) -- se nao
// funcionar, volta pro patch binario em tools/patch_deauth_sanity_check.py.
#include <cstdint>

extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg1, int32_t arg2, int32_t arg3) {
  return 0;
}
