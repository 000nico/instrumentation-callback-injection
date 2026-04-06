#include <windows.h>

typedef HANDLE (WINAPI* pCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

typedef BOOL (WINAPI* pBeep)(DWORD, DWORD);

typedef void (WINAPI* pSleep)(DWORD);

struct payloadStruct {
    pBeep         beep;
    pCreateThread createThread;
    pSleep sleep;
};