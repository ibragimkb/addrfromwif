CC = gcc
CFLAGS =  -fPIC -std=gnu99 -pedantic -W -Wall -Wno-missing-braces

LIB_PATH = ../libbtc


# build C lib
main: main.o altchainparams.o zec_ecc_key.o
	$(CC) altchainparams.o zec_ecc_key.o main.o -o addrFromWif -s $(LIB_PATH)/.libs/libbtc.a $(LIB_PATH)/src/secp256k1/.libs/libsecp256k1.a

main.o: main.c main.h
	$(CC) $(CFLAGS) -I$(LIB_PATH)/include/ -DNO_LUA_WRAP -c main.c -o main.o

altchainparams.o: altchainparams.c altchainparams.h
	$(CC) $(CFLAGS) -I$(LIB_PATH)/include/ -DNO_LUA_WRAP -c altchainparams.c -o altchainparams.o

zec_ecc_key.o: zec_ecc_key.c zec_ecc_key.h
	$(CC) $(CFLAGS) -I$(LIB_PATH)/include/ -DNO_LUA_WRAP -c zec_ecc_key.c -o zec_ecc_key.o

clean: 
	rm -f *.o main
