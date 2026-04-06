#include "syringe.hpp"
#include "../wrapper/bin/wrapper.hpp"
#include <winternl.h>
#include <iostream>

LPVOID payloadBaseAddr;
LPVOID wrapperBaseAddr;
LPVOID structBaseAddr;

#define _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION 40

bool enableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp = {};
    
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid);
    
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return true;
}

bool allocateMemory(HANDLE handle, size_t size){
    wrapperBaseAddr = VirtualAllocEx(handle, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(!wrapperBaseAddr) return 0;

    payloadBaseAddr = VirtualAllocEx(handle, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(!payloadBaseAddr) return 0;

    return true;
}

bool writeMemory(HANDLE handle, unsigned char* payload, unsigned int lenght){
    bool writeWrapper = WriteProcessMemory(handle, wrapperBaseAddr, bin_wrapper_bin, bin_wrapper_bin_len, 0);
    bool writeMemory = WriteProcessMemory(handle, payloadBaseAddr, payload, lenght, 0);
    if(!writeMemory || !writeWrapper) return 0;
    return true;
}

int replacePlaceHolder(){
    BYTE pattern[] = { 0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE };

    for(int i = 0; i < bin_wrapper_bin_len - 10; i++){
        if(memcmp(&bin_wrapper_bin[i], pattern, 10) == 0){
            memcpy(&bin_wrapper_bin[i + 2], &payloadBaseAddr, 8);
            return i;
        }
    }

    return -1;
}

int allocateAndWriteStructure(HANDLE handle, void* structPointer, size_t size){
    structBaseAddr = VirtualAllocEx(handle, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(!structBaseAddr) return 0;

    bool writeStruct = WriteProcessMemory(handle, structBaseAddr, structPointer, size, 0);
    if(!writeStruct) return 0;

    return true;
}

int replaceStructPlaceHolderPayload(unsigned char* payload, unsigned int payloadSize, BYTE* pattern, unsigned int patternSize){
    for(int i = 0; i < payloadSize - patternSize; i++){
        if(memcmp(&payload[i], pattern, patternSize) == 0){
            memcpy(&payload[i], &structBaseAddr, sizeof(void*));
            return i;
        }
    }
    
    return -1;
}

bool setProcessCallback(HANDLE handle){
    fnNtSetInformationProcess_t NtSetInformationProcess = (fnNtSetInformationProcess_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");

    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION PICI;
    PICI.Version = 0;
    PICI.Reserved = 0;
    PICI.Callback = wrapperBaseAddr;
    NTSTATUS status = NtSetInformationProcess(handle, _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, &PICI, sizeof(PICI));

    if(!NT_SUCCESS(status)) return 0;
    return true;
}

bool PICII::inject(HANDLE handle, size_t size, unsigned char* payload, unsigned int lenght, void* structPointer, size_t structSize, BYTE* pattern, unsigned int patternSize, bool debug){
    // 1. Enable privilege
    if(!enableDebugPrivilege()) return -2;
    if(debug) std::cout << "[PICII] enabled se debug privilege" << std::endl;

    // 2. Allocate memory for the wrapper and payload
    if(!allocateMemory(handle, size)) return -3;
    if(debug) std::cout << "[PICII] wrapper memory allocated at " << std::hex << wrapperBaseAddr << std::endl;
    if(debug) std::cout << "[PICII] payload memory allocated at " << std::hex << payloadBaseAddr << std::endl;

    // 3. Replace the placeholder of the wrapper, to call the payload correctly
    int pos = replacePlaceHolder();
    if(pos == -1) return -4;
    if(debug) std::cout << "[PICII] placeholder found at pos: " << pos << std::endl;
    if(debug) std::cout << "[PICII] placeholder replaced with: " << std::hex << payloadBaseAddr << std::endl;

    // 4. Structures
    if(!allocateAndWriteStructure(handle, structPointer, structSize)) return -5;
    if(debug) std::cout << "[PICII] allocatted structure at: " << std::hex << structBaseAddr << std::endl;
    if(debug) std::cout << "[PICII] structure written" << std::endl;

    int posStruct = replaceStructPlaceHolderPayload(payload, lenght, pattern, patternSize);
    if(posStruct == -1) return -6;
    if(debug) std::cout << "[PICII] replaced placeholder structure of the payload at the pos " << std::dec << posStruct << std::endl;
    
    // 5. Write the payload in memory
    if(!writeMemory(handle, payload, lenght)) return -7;
    if(debug) std::cout << "[PICII] memory written" << std::endl;

    // 6. Set instrumentation callback
    if(!setProcessCallback(handle)) return -8;
    if(debug) std::cout << "[PICII] process instrumentation callback information set" << std::endl;

    return true;
}

bool PICII::exit(HANDLE handle, bool debug){
    fnNtSetInformationProcess_t NtSetInformationProcess = (fnNtSetInformationProcess_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");

    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION PICI;
    PICI.Reserved = 0;
    PICI.Version = 0;
    PICI.Callback = NULL;
    NtSetInformationProcess(handle, _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, &PICI, sizeof(PICI));

    if(!VirtualFreeEx(handle, payloadBaseAddr, 0, MEM_RELEASE)) return 0;
    if(debug) std::cout << "[PICII] released memory" << std::endl;
    return true;
}