#ifndef PROCHIDER_INTERNAL_HOOK_H
#define PROCHIDER_INTERNAL_HOOK_H
#endif

#include "phnt_windows.h"
#include "phnt.h"
#include "stdio.h"

typedef struct hookInfo_s
{
    void* originalFunc;
    void* detourFunc;
    void* trampFunc;
    unsigned char backupBytes[256];
    SIZE_T length;
}hookInfo;

typedef NTSTATUS (_stdcall* NtQuerySystemInfoFunc)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID
SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

NTSTATUS hkNtQuerySystemInfo(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID
SystemInformation, ULONG SystemInformationLength,PULONG ReturnLength);

void Tramp64(void* pTarget, void* pDetour, void** ppOriginal, unsigned int len, unsigned char* backupBytes);

void restore(void* pTarget, unsigned char* backupBytes, unsigned int len);