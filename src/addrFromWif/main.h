#ifndef MAIN_H
#define MAIN_H

#include <btc/bip32.h>
#include <btc/tool.h>
#include <btc/utils.h>
#include <btc/memory.h>

#include "altchainparams.h"

#ifndef CGENHDADDRS_MODNAME
#define CGENHDADDRS_MODNAME   "cgenhdaddrs"
#endif

#ifndef CGENHDADDRS_VERSION
#define CGENHDADDRS_VERSION   "3.1.0"
#endif

#define PATH_LEN 128
#define BASEPATH_LEN 64
#define ADDR_BUFF_LEN 64
/*#define ADDR_BUFF_LEN 129*/
#define START_NUM_LEN 16
#define ERR_BUF_LEN 256

#define DEFAULT_MAX_ADDR 10000
#define Kf 1024
/*#define MIN_ADDR_LEN 32*/
#define XPUB_MAX_LEN 256
#define XPUB_MIN_LEN 100

#define NAME_LABEL_LEN 16
#define KEY_LABEL_LEN 4

extern void btc_ecc_start();
extern void btc_ecc_stop();

#endif // MAIN_H

