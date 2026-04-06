#!/bin/bash
mkdir -p bin
x86_64-w64-mingw32-g++ \
    -O1 \
    -nostdlib \
    -fno-stack-protector \
    -fno-exceptions \
    -fno-rtti \
    -fPIC \
    -c wrapper.cpp -o bin/wrapper.o

objdump -d bin/wrapper.o