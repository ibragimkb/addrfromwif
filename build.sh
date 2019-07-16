#!/bin/bash

WDIR="$(pwd)"
TEMPDIR="$WDIR/tmp"
LIB_FILE="libbtc-master.zip"

NAME="addrFromWif"
#TAR_FILE=$NAME".tar.gz"
BINDIR="$WDIR/bin"
BIN_FILE=$NAME

if [ -d $TEMPDIR ] ; then
    rm -rf $TEMPDIR
    mkdir -p $TEMPDIR
fi

if [ -d $BINDIR ] ; then
    rm -rf $BINDIR
fi
mkdir -p $BINDIR


unzip src/$LIB_FILE -d $TEMPDIR
#tar xf src/$TAR_FILE -C $TEMPDIR
cp -r src/$NAME/ $TEMPDIR/

cd $TEMPDIR/libbtc-master
patch -p1 < ../$NAME/addypub.diff
./autogen.sh
./configure --disable-shared --enable-static --disable-net --disable-wallet --disable-tools CFLAGS="$CFLAGS -fPIC"
make

cd $TEMPDIR/$NAME
make clean
make

if [ -f $TEMPDIR/$NAME/$BIN_FILE ] ; then
    cp $TEMPDIR/$NAME/$BIN_FILE $BINDIR/
fi

#cd $TEMPDIR/$LIBNAME/test
#make
