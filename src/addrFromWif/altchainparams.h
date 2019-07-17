#ifndef ALTCHAINPARAMS_H
#define ALTCHAINPARAMS_H

#include "main.h"

enum {
    BTC_XPUB =  1,
    BTC_YPUB =  2,
    DASH_XPUB = 3,
    DASH_DRKP = 4,
    LTC_MTUB =  5,
    LTC_XPUB =  6,
    LTC_YPUB =  7,
    ZEC_XPUB =  8,
    ZEC_YPUB =  9
};

typedef struct zec_chainparams_ {
    char chainname[32];
    uint16_t b58prefix_pubkey_address;
    uint16_t b58prefix_script_address;
    const char bech32_hrp[5];
    uint8_t b58prefix_secret_address; //!private key
    uint32_t b58prefix_bip32_privkey;
    uint32_t b58prefix_bip32_pubkey;
    const unsigned char netmagic[4];
    uint256 genesisblockhash;
    int default_port;
    btc_dns_seed dnsseeds[8];
} zec_chainparams;

extern const char *CURRENCY;
extern const btc_chainparams btc_chainparams_main_ypub;
extern const btc_chainparams dash_chainparams_xpub;
extern const btc_chainparams dash_chainparams_drkp;
extern const btc_chainparams ltc_chainparams_mtub;
extern const zec_chainparams zec_chainparams_xpub;


int getCurrencyChainType(const char *currency, const char *key);
int currencyVerify(const char *currency);

#endif // ALTCHAINPARAMS_H

