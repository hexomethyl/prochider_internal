#include "hook.h"

HINSTANCE g_dllHandle;
hookInfo g_NtQuerySysInfoHook;

void mainThread()
{
    AllocConsole();
    FILE* oldStdOut = NULL;
    freopen_s(&oldStdOut, "CONOUT$", "w", stdout);

    HMODULE hNtdll = GetModuleHandle("ntdll.dll");
    g_NtQuerySysInfoHook.originalFunc = (NtQuerySystemInfoFunc)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    g_NtQuerySysInfoHook.detourFunc = &hkNtQuerySystemInfo;
    g_NtQuerySysInfoHook.length = 0x12;
    memset(g_NtQuerySysInfoHook.backupBytes,0,256);
    printf("NtQuerySystemInformation: 0x%p\n", g_NtQuerySysInfoHook.originalFunc);

    Tramp64(g_NtQuerySysInfoHook.originalFunc, g_NtQuerySysInfoHook.detourFunc, &(g_NtQuerySysInfoHook.trampFunc),
            g_NtQuerySysInfoHook.length,
            g_NtQuerySysInfoHook.backupBytes);
    printf("Detour NtQuerySystemInformation: 0x%p\n",  g_NtQuerySysInfoHook.detourFunc);
    printf("Trampoline NtQuerySystemInformation: 0x%p\n", g_NtQuerySysInfoHook.trampFunc);
    
    while (1)
    {
        if (GetAsyncKeyState(VK_DELETE) & 0x8000)
            break;
        Sleep(10);
    }

    restore(g_NtQuerySysInfoHook.originalFunc, g_NtQuerySysInfoHook.backupBytes, g_NtQuerySysInfoHook.length);

    fclose(oldStdOut);
    FreeConsole();
    FreeLibraryAndExitThread(g_dllHandle, 0);

}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,  // handle to DLL module
                    DWORD fdwReason,     // reason for calling function
                    LPVOID lpReserved)  // reserved
{
    // Perform actions based on the reason for calling.
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        g_dllHandle = hinstDLL;
        CloseHandle(CreateThread(NULL, (SIZE_T)NULL, (LPTHREAD_START_ROUTINE)mainThread, NULL, 0, NULL));
        return TRUE;  // Successful DLL_PROCESS_ATTACH.
    }

    return FALSE;
}