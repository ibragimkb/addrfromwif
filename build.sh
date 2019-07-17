#!/bin/bash

WDIR="$(pwd)"

NAME="addrFromWif"

BINDIR="$WDIR/bin"
SRCDIR="$WDIR/src"
APPDIR="$SRCDIR/$NAME"
LIBBTC="$SRCDIR/libbtc"

if [ -d $BINDIR ] ; then
    rm -f $BINDIR/$NAME
else
    mkdir -p $BINDIR
fi

cd $LIBBTC
make clean
./autogen.sh
./configure --disable-shared --enable-static --disable-net --disable-wallet --disable-tools CFLAGS="$CFLAGS -fPIC"
make

cd $APPDIR
make clean
make

if [ -f $APPDIR/$NAME ] ; then
    mv $APPDIR/$NAME $BINDIR/
    echo "Successfully"
else
    echo "Failure"
fi
