/*
 * get ZEC HD adresses 
 * 
 * Copyright 2018 ibragim <i826.508@gmail.com>
 * 
 */

#include <assert.h>
#include <btc/base58.h>
#include <btc/ecc.h>
#include <btc/ecc_key.h>
#include "altchainparams.h"
#include "zec_ecc_key.h"

static btc_bool zec_hdnode_deserialize(const char* str, const zec_chainparams* chain, btc_hdnode* node);
/*static btc_bool zec_pubkey_getaddr_p2pkh(const btc_pubkey* pubkey, const zec_chainparams* chain, char *addrout);*/

#ifdef LUA_WRAP
int getZecAddrsByPubKey(lua_State *L, const int keytype, const char *masterkey, const char *derive_path, const unsigned int start, const unsigned int addrs_num, char *err_buffer, const int err_sz)
#else
int getZecAddrsByPubKey(const int keytype, const char *masterkey, const char *derive_path, const unsigned int start, const unsigned int addrs_num, char *out_addr, int buf_sz, char *err_buffer, const int err_sz)
#endif
{
    const zec_chainparams* chain;
    btc_hdnode node, nodenew;
    btc_pubkey pubkey;
    btc_bool pubckd;
    char addr[ADDR_BUFF_LEN];
    char keypath[PATH_LEN];
    unsigned int i, n;
#ifndef LUA_WRAP
    unsigned int e;
    char *p = out_addr;
#endif

    switch (keytype) {
        case ZEC_XPUB:
            chain = &zec_chainparams_xpub;
        break;

        default:
            snprintf(err_buffer, err_sz, "invalid keytype %d", keytype);
            return 0;
    }

    btc_ecc_start();
    btc_pubkey_init(&pubkey);
    if (!zec_hdnode_deserialize(masterkey, chain, &node)) {
        snprintf(err_buffer, err_sz, "pubkey \"%s\" is not valid", masterkey);
        btc_ecc_stop();
        return -1;
    }
    pubckd = !btc_hdnode_has_privkey(&node);
    n = addrs_num + start;

#ifdef LUA_WRAP
    lua_createtable(L, 0, addrs_num); /* addrs_num - number of fields */
#else
    e = n - 1;
#endif

    for (i=start; i<n; i++) {
        memset(addr, 0, ADDR_BUFF_LEN);
        memset(keypath, 0, sizeof(keypath));
        snprintf(keypath, PATH_LEN - 1, "%s%d", derive_path, i);    

        if (!btc_hd_generate_key(&nodenew, keypath, node.public_key, node.chain_code, pubckd)) {
            snprintf(err_buffer, err_sz, "btc_hd_generate_key failed from keypath \"%s\"", keypath);
            btc_ecc_stop();
            return 0;
        }

        btc_pubkey_cleanse(&pubkey);
        pubkey.compressed = 1;
        memcpy(&pubkey.pubkey, nodenew.public_key, sizeof(nodenew.public_key));

        if (!btc_pubkey_is_valid(&pubkey)) {
            snprintf(err_buffer, err_sz, "%s", "generated hd pubkey is not valid");
            btc_ecc_stop();
            return 0;
        }
        switch (keytype) {
            case ZEC_XPUB:
                zec_pubkey_getaddr_p2pkh(&pubkey, chain, addr);
            break;
            
            default:
                snprintf(err_buffer, err_sz, "pubkey_getaddr invalid keytype %d", keytype);
                btc_ecc_stop();
                return 0;
        }

#ifdef LUA_WRAP
        lua_pushstring(L, addr);
        lua_setfield(L, -2, keypath);
#else
        if ((int)strlens(addr) + 1 >= buf_sz) {
            snprintf(err_buffer, err_sz, "address \"%s\" length greater than buffer size %d", addr, buf_sz);
            btc_ecc_stop();
            return 0;
        }
        if (i == e) {
            p+=snprintf(p, buf_sz, "%s", addr);
            buf_sz = buf_sz - strlens(addr);
        }
        else {
            p+=snprintf(p, buf_sz, "%s|", addr);
            buf_sz = buf_sz - strlens(addr) - 1;
        }
#endif
    }
    btc_ecc_stop();
    return i-start;
}

// read 4 big endian bytes
static uint32_t read_be(const uint8_t* data)
{
    return (((uint32_t)data[0]) << 24) |
           (((uint32_t)data[1]) << 16) |
           (((uint32_t)data[2]) << 8) |
           (((uint32_t)data[3]));
}

// check for validity of curve point in case of public data not performed
static btc_bool zec_hdnode_deserialize(const char* str, const zec_chainparams* chain, btc_hdnode* node)
{
    uint8_t node_data[strlen(str)];
    memset(node, 0, sizeof(btc_hdnode));
    size_t outlen = 0;

    outlen = btc_base58_decode_check(str, node_data, sizeof(node_data));
    if (!outlen) {
        return false;
    }
    uint32_t version = read_be(node_data);
    if (version == chain->b58prefix_bip32_pubkey) { // public node
        memcpy(node->public_key, node_data + 45, BTC_ECKEY_COMPRESSED_LENGTH);
    } else if (version == chain->b58prefix_bip32_privkey) { // private node
        if (node_data[45]) {                                // invalid data
            return false;
        }
        memcpy(node->private_key, node_data + 46, BTC_ECKEY_PKEY_LENGTH);
        btc_hdnode_fill_public_key(node);
    } else {
        return false; // invalid version
    }
    node->depth = node_data[4];
    node->fingerprint = read_be(node_data + 5);
    node->child_num = read_be(node_data + 9);
    memcpy(node->chain_code, node_data + 13, BTC_BIP32_CHAINCODE_SIZE);
    return true;
}

btc_bool zec_pubkey_getaddr_p2pkh(const btc_pubkey* pubkey, const zec_chainparams* chain, char *addrout)
{
    uint8_t hash160[sizeof(uint160)+2];
    *((uint16_t *)&hash160[0]) = chain->b58prefix_pubkey_address;
    btc_pubkey_get_hash160(pubkey, hash160 + 2);
    btc_base58_encode_check(hash160, sizeof(hash160), addrout, 100);
    return true;
}

void zec_privkey_encode_wif(const btc_key* privkey, const zec_chainparams* chain, char *privkey_wif, size_t *strsize_inout) {
    uint8_t pkeybase58c[34];
    pkeybase58c[0] = chain->b58prefix_secret_address;
    pkeybase58c[33] = 1; /* always use compressed keys */

    memcpy(&pkeybase58c[1], privkey->privkey, BTC_ECKEY_PKEY_LENGTH);
    assert(btc_base58_encode_check(pkeybase58c, 34, privkey_wif, *strsize_inout) != 0);
    btc_mem_zero(&pkeybase58c, 34);
}

btc_bool zec_privkey_decode_wif(const char *privkey_wif, const zec_chainparams* chain, btc_key* privkey)
{

    if (!privkey_wif || strlen(privkey_wif) < 50) {
        return false;
    }
    uint8_t privkey_data[strlen(privkey_wif)];
    memset(privkey_data, 0, sizeof(privkey_data));
    size_t outlen = 0;

    outlen = btc_base58_decode_check(privkey_wif, privkey_data, sizeof(privkey_data));
    if (!outlen) {
        return false;
    }
    if (privkey_data[0] != chain->b58prefix_secret_address) {
        return false;
    }
    memcpy(privkey->privkey, &privkey_data[1], BTC_ECKEY_PKEY_LENGTH);
    btc_mem_zero(&privkey_data, sizeof(privkey_data));
    return true;
}
