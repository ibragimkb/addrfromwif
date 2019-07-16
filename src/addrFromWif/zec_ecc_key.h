#ifndef ZEC_ECC_KEY_H
#define ZEC_ECC_KEY_H

#ifdef LUA_WRAP
int getZecAddrsByPubKey(lua_State *L, const int keytype, const char *masterkey, const char *derive_path, const unsigned int start, const unsigned int addrs_num, char *err_buffer, const int err_sz);
#else
int getZecAddrsByPubKey(const int keytype, const char *masterkey, const char *derive_path, const unsigned int start, const unsigned int addrs_num, char *out_addr, int buf_sz, char *err_buffer, const int err_sz);
#endif
btc_bool zec_pubkey_getaddr_p2pkh(const btc_pubkey* pubkey, const zec_chainparams* chain, char *addrout);
void zec_privkey_encode_wif(const btc_key* privkey, const zec_chainparams* chain, char *privkey_wif, size_t *strsize_inout);
btc_bool zec_privkey_decode_wif(const char *privkey_wif, const zec_chainparams* chain, btc_key* privkey);

#endif // ZEC_ECC_KEY_H

