/*
 * main.c
 * 
 * Copyright 2018 ibragim <i826.508@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 * 
 */


#include <stdio.h>
#include <unistd.h>

#include "altchainparams.h"
#include "zec_ecc_key.h"

int getPubAddressFromWIF(const int currency_type,  const char *pkey_wif, 
            char *addr, int addr_sz, char *err_buffer, const int err_sz)
{
    const void* chain;
    btc_key privkey;
    btc_pubkey pubkey;

    if (ADDR_BUFF_LEN > addr_sz) {
        snprintf(err_buffer, err_sz, "[E] address buffer length %d less %d", addr_sz, ADDR_BUFF_LEN);
        return 0;
    }

    switch (currency_type) {
        case BTC_XPUB:
        case LTC_XPUB:
            chain = (btc_chainparams *)&btc_chainparams_main;
        break;
        case BTC_YPUB:
            chain = (btc_chainparams *)&btc_chainparams_main_ypub;
        break;
        case DASH_XPUB:
            chain = (btc_chainparams *)&dash_chainparams_xpub;
        break;
        case DASH_DRKP:
            chain = (btc_chainparams *)&dash_chainparams_drkp;
        break;
        case LTC_MTUB:
            chain = (btc_chainparams *)&ltc_chainparams_mtub;
        break;
        case ZEC_XPUB:
            chain = (zec_chainparams *)&zec_chainparams_xpub;
        break;
        default:
            snprintf(err_buffer, err_sz, "[E] invalid currency or address type %d", currency_type);
            return 0;
    }

    btc_ecc_start();
    
    btc_privkey_init(&privkey);

    switch (currency_type) {
        case ZEC_XPUB:
            if (!zec_privkey_decode_wif(pkey_wif, chain, &privkey)) {
                snprintf(err_buffer, err_sz, "[E] invalid zec wif '%s' decode", pkey_wif);
                btc_ecc_stop();
                return 0;
            }
        break;
        case BTC_XPUB:
        case LTC_XPUB:
        case BTC_YPUB:
        case DASH_XPUB:
        case DASH_DRKP:
        case LTC_MTUB:
            if (!btc_privkey_decode_wif(pkey_wif, chain, &privkey)) {
                snprintf(err_buffer, err_sz, "[E] invalid wif '%s' decode", pkey_wif);
                btc_ecc_stop();
                return 0;
            }
        break;
        default:
            snprintf(err_buffer, err_sz, "[E] invalid currency or address type %d", currency_type);
            btc_ecc_stop();
            return 0;
        break;
    }

    btc_pubkey_init(&pubkey);
    btc_pubkey_from_key(&privkey, &pubkey);

    switch (currency_type) {
        case BTC_XPUB:
        case DASH_XPUB:
        case DASH_DRKP:
            btc_pubkey_getaddr_p2pkh(&pubkey, chain, addr);
        break;
        case BTC_YPUB:
        case LTC_MTUB:
            btc_pubkey_getaddr_p2sh_p2wpkh(&pubkey, chain, addr);
        break;
        case LTC_XPUB:
            btc_pubkey_getaddr_p2pkh(&pubkey, &ltc_chainparams_mtub, addr);
        break;
        case ZEC_XPUB:
            zec_pubkey_getaddr_p2pkh(&pubkey, chain, addr);
        break;

        default:
            snprintf(err_buffer, err_sz, "[E] invalid currency or address type %d", currency_type);
            btc_ecc_stop();
            return 0;
    }

    if (!btc_privkey_verify_pubkey(&privkey, &pubkey)) {
        snprintf(err_buffer, err_sz, "[E] privkey_verify_pubkey failed %s", pkey_wif);
        btc_ecc_stop();
        return 0;
    }
    if (!btc_pubkey_is_valid(&pubkey)) {
        snprintf(err_buffer, err_sz, "[E] pubkey_is_valid failed %s", pkey_wif);
        btc_ecc_stop();
        return 0;
    }

    btc_ecc_stop();
    return 1;
}

static int genWif(const int currency_type, char *wifstr, size_t *wifstr_sz, char *err_buffer, const int err_sz)
{
    const void* chain;
    btc_key key_wif;
    
    if (ADDR_BUFF_LEN > *wifstr_sz) {
        snprintf(err_buffer, err_sz, "[E] wif buffer length %ld less %d", *wifstr_sz, ADDR_BUFF_LEN);
        return 0;
    }

    switch (currency_type) {
        case BTC_XPUB:
        case LTC_XPUB:
            chain = (btc_chainparams *)&btc_chainparams_main;
        break;
        case BTC_YPUB:
            chain = (btc_chainparams *)&btc_chainparams_main_ypub;
        break;
        case DASH_XPUB:
            chain = (btc_chainparams *)&dash_chainparams_xpub;
        break;
        case DASH_DRKP:
            chain = (btc_chainparams *)&dash_chainparams_drkp;
        break;
        case LTC_MTUB:
            chain = (btc_chainparams *)&ltc_chainparams_mtub;
        break;
        case ZEC_XPUB:
            chain = (zec_chainparams *)&zec_chainparams_xpub;
        break;
        default:
            snprintf(err_buffer, err_sz, "[E] invalid currency or address type %d", currency_type);
            return 0;
    }

    btc_ecc_start();
    btc_privkey_init(&key_wif);
    btc_privkey_gen(&key_wif);
    if (!btc_privkey_is_valid(&key_wif)) {
        snprintf(err_buffer, err_sz, "[E] %s", "privkey is not valid ");
        btc_ecc_stop();
        return 0;
    }
    
    switch (currency_type) {
        case ZEC_XPUB:
            zec_privkey_encode_wif(&key_wif, chain, wifstr, wifstr_sz);
        break;
        case BTC_XPUB:
        case LTC_XPUB:
        case BTC_YPUB:
        case DASH_XPUB:
        case DASH_DRKP:
        case LTC_MTUB:
            btc_privkey_encode_wif(&key_wif, chain, wifstr, wifstr_sz);
        break;
        default:
            snprintf(err_buffer, err_sz, "[E] invalid currency or address type %d", currency_type);
            btc_ecc_stop();
            return 0;
        break;
    }    
    
    btc_ecc_stop();
    return 1;
}

/*void test()
{
    const int addr_sz = 128;
    const int err_sz = 512;
    char addr[addr_sz];
    char err_buffer[err_sz];
    const char *pkey_wif = {"L3ax2Kicb8KWuEKSEhaUixLzaz4Fy5YTvcPecGc6z7Y2WwvJvm12"};
    const char *zec_pkey_wif = {"Kxn9jeGUkzh13EQZgqP2tVYESyercbothUcKU58qLMCtYYpvtX9B"};
    char wifstr[100];
    size_t wiflen = 100;    

    genWif(BTC_XPUB, wifstr, &wiflen, err_buffer, err_sz);
    printf("wif: [%s] %ld\n", wifstr, wiflen);
    getPubAddressFromWIF(BTC_XPUB,  wifstr, addr, addr_sz, err_buffer, err_sz);
    printf("addr: %s\n\n", addr);

    memset(wifstr, 0, sizeof(wifstr));
    genWif(ZEC_XPUB, wifstr, &wiflen, err_buffer, err_sz);
    printf("wif: [%s] %ld\n", wifstr, wiflen);
    getPubAddressFromWIF(ZEC_XPUB,  wifstr, addr, addr_sz, err_buffer, err_sz);
    printf("addr: %s\n\n", addr);

    getPubAddressFromWIF(BTC_XPUB,  pkey_wif, addr, addr_sz, err_buffer, err_sz);
    printf("addr: %s\n\n", addr);
    getPubAddressFromWIF(ZEC_XPUB,  zec_pkey_wif, addr, addr_sz, err_buffer, err_sz);
    printf("addr: %s\n\n", addr);
}*/

int getId(const char *currency, const char *addr_type)
{
    if (0 == strcmp(addr_type,"pkh")) {
        if (0 == strcmp(currency,"btc")) return BTC_XPUB;
        if (0 == strcmp(currency,"dash")) return DASH_XPUB;
        if (0 == strcmp(currency,"ltc")) return LTC_XPUB;
        if (0 == strcmp(currency,"zec")) return ZEC_XPUB;
    }
    else if (0 == strcmp(addr_type,"wpkh")) {
        if (0 == strcmp(currency,"btc")) return BTC_YPUB;
        if (0 == strcmp(currency,"ltc")) return LTC_MTUB;
    }
    return 0;
}

void usage(const char *app)
{
    printf("\tHelp:\n");
    printf("\t-c - currency name: (btc, dash, ltc, zec)\n");
    printf("\t-w - wif\n");
    printf("\t-t - address type: (pkh, wpkh)\n");
    printf("Example:\n%s -t btc\n", app);
    printf("%s -c btc -w L3ax2Kicb8KWuEKSEhaUixLzaz4Fy5YTvcPecGc6z7Y2WwvJvm12\n\n", app);
    printf("%s -c btc -t wpkh -w L3ax2Kicb8KWuEKSEhaUixLzaz4Fy5YTvcPecGc6z7Y2WwvJvm12\n\n", app);
	printf("Gen address without wif (new wif auto generated)\n%s -c btc -t wpkh\n\n", app);
}

int main(int argc, char **argv)
{

    const unsigned int BUFFER_LEN = 5;
    const unsigned int WIF_BUFFER_LEN = 128;
    int opt;
    int err = 0;
    char currency[BUFFER_LEN];
    char addr_type[BUFFER_LEN];
    char wif[WIF_BUFFER_LEN];
    size_t wiflen = WIF_BUFFER_LEN;
    const int addr_sz = 128;
    const int err_sz = 512;
    char addr[addr_sz];
    char err_buffer[err_sz];
    int id = 0;

    if (argc < 2) {
        usage(argv[0]);
        return 0;
    }
    memset(currency, 0, sizeof(currency));
    memset(addr_type, 0, sizeof(addr_type));
    memset(wif, 0, sizeof(wif));
    memcpy(addr_type, "pkh", 3);
    
    while(((opt = getopt(argc, argv, ":c:t:w:h")) != -1) && !err)
    {
        switch(opt)
        {
            case 'h':
                err = 2;
            break;
            case 'w':
                if (WIF_BUFFER_LEN > strlen(optarg)) {
                    memcpy(wif, optarg, strlen(optarg));
                }
                else {
                    err = 1;
                }
            break;
            case 't':
                if (0 == strcmp(optarg,"pkh") || 0 == strcmp(optarg,"wpkh")) {
                    memcpy(addr_type, optarg, strlen(optarg));
                }
                else {
                    err = 1;
                }
            break;
            case 'c':
                if (BUFFER_LEN >= strlen(optarg) && currencyVerify(optarg)) {
                    memcpy(currency, optarg, strlen(optarg));
                }
                else {
                    err = 1;
                }
            break;
            case ':': 
                printf("option '-%c' needs a value\n", optopt);
                err = 2;
            break;
            case '?':
                printf("unknown option: %c\n", optopt);
                err = 1;
            break;
        }
    }

    switch(err) {
        case 0:
            id = getId(currency, addr_type);            
            if (id) {
                if (0 == strlen(wif)) {
                    if (!genWif(id, wif, &wiflen, err_buffer, err_sz)) {
                        printf("[E] gen wif fail; %s\n", err_buffer);
                        return 0;
                    }
					printf("\n!!! wif undefined\n\tGenerate new wif: %s\n", wif);
                }
                if (!getPubAddressFromWIF(id,  wif, addr, addr_sz, err_buffer, err_sz)) {
                    printf("[E] %s\n", err_buffer);
                    return 0;
                }
                printf("\nwif: %s\naddress: %s\naddress type: %s\n", wif, addr, addr_type);
            }
            else {
                printf("[E] invalid currency (%s) or address (%s)\n", currency, addr_type);
            }
        break;
        case 1:
            printf("incorrect params. for help: %s -h\n", argv[0]);
        break;
        default:
            usage(argv[0]);
        break;
    }
    return 0;
}
