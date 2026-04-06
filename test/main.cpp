#include "../syringe/syringe.hpp"
#include "payload/bin/payload.hpp"
#include "main.hpp"
#include <iostream>

int main(){

    HWND hwnd = FindWindowA(nullptr, "Untitled - Notepad");
    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);

    std::cout << "[test] pid = " << pid << std::endl;
    
    // pattern
    BYTE pattern[] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };

    // struct
    payloadStruct ps = {};
    ps.beep         = (pBeep)        GetProcAddress(GetModuleHandle("kernel32.dll"), "Beep");
    ps.createThread = (pCreateThread)GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateThread");
    ps.sleep = (pSleep)GetProcAddress(GetModuleHandle("kernel32.dll"), "Sleep");
    
    HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    PICII::inject(handle, 
        0x1000, 
        (unsigned char*)bin_payload_bin, 
        bin_payload_bin_len, 
        &ps,
        sizeof(ps),
        pattern,
        8,
        true);

    Sleep(20000);

    PICII::exit(handle, true);
    CloseHandle(handle);
}