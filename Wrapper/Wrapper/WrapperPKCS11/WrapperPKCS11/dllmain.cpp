#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ulReasonForCall,
    LPVOID lpReserved)
{
    switch (ulReasonForCall)
    {
    case DLL_PROCESS_ATTACH:
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}