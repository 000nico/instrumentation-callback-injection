#include <windows.h>
#include <winternl.h>
#include "../main.hpp"

extern "C" void payload(){
    volatile uintptr_t structPlaceHolder = 0xAAAAAAAAAAAAAAAA;

    static volatile int executed = 0;
    if(executed) return;
    executed = 1;
}