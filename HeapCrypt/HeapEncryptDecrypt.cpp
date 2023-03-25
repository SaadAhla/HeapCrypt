#define _CRT_RAND_S
#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

void (WINAPI* pSleep)(
    DWORD dwMilliseconds
) = Sleep;


void SuspendThreads(DWORD mainThread) {

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hSnapshot, &te32))
        return;

    do {
        if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != mainThread) {

            SuspendThread(OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID));
        }
    } while (Thread32Next(hSnapshot, &te32));
}


void ResumeThreads(DWORD mainThread) {

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hSnapshot, &te32))
        return;

    do {
        if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != mainThread) {

            ResumeThread(OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID));
        }
    } while (Thread32Next(hSnapshot, &te32));

}




void XorIT(BYTE* input, size_t length, BYTE key[16]) {
    int key_length = sizeof(key);

    for (int i = 0; i < length; i++) {
        input[i] = input[i] ^ key[i % key_length];
    }
}



void HeapEncryptDecrypt(BYTE KeyBuf[16]) {

   
    PROCESS_HEAP_ENTRY entry;
    SecureZeroMemory(&entry, sizeof(entry));
    while (HeapWalk(GetProcessHeap(), &entry)) {
        if ((entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0) {
            XorIT((BYTE*)entry.lpData, entry.cbData, KeyBuf);
            
        }

    }

}


// our Hooking function
void HeapSleep(DWORD dwMilliseconds) {
    
    BYTE KeyBuf[16];
    unsigned int r = 0;
    for (int i = 0; i < 16; i++) {
        rand_s(&r); 
        KeyBuf[i] = (CHAR)r;

    }
    
    printf("[+] Encrypt the HEAP allocations\n");
    HeapEncryptDecrypt(KeyBuf);

    
    pSleep(dwMilliseconds);
    
    HeapEncryptDecrypt(KeyBuf);

    printf("[+] Decrypt the Heap allocations\n");
    pSleep(dwMilliseconds);

}



BOOL Hookit(char* dllName, char* func, PROC myFunc) {

    HANDLE baseAddress = GetModuleHandle(NULL);
    IMAGE_DOS_HEADER* DOS_HEADER = (IMAGE_DOS_HEADER*)baseAddress;
    IMAGE_NT_HEADERS* NT_HEADER = (IMAGE_NT_HEADERS*)((DWORD64)baseAddress + DOS_HEADER->e_lfanew);


    IMAGE_IMPORT_DESCRIPTOR* IMPORT_DATA = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD64)baseAddress + NT_HEADER->OptionalHeader.DataDirectory[1].VirtualAddress);

    LPCSTR ModuleName = "";
    BOOL found = FALSE;

    while (IMPORT_DATA->Name != NULL) {
        ModuleName = (LPCSTR)IMPORT_DATA->Name + (DWORD64)baseAddress;
        if (_stricmp(ModuleName, dllName) == 0) {
            found = TRUE;
            break;
        }
        IMPORT_DATA++;
    }

    if (!found)
        return FALSE;

    PROC Sleep = (PROC)GetProcAddress(GetModuleHandleA(dllName), func);

    PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((PBYTE)baseAddress + IMPORT_DATA->FirstThunk);
    while (thunk->u1.Function) {
        PROC* FunctionAddr = (PROC*)&thunk->u1.Function;


        if (*FunctionAddr == Sleep) {


            DWORD oldProtect = 0;
            VirtualProtect((LPVOID)FunctionAddr, 4096, PAGE_READWRITE, &oldProtect);

            *FunctionAddr = (PROC)myFunc;

            VirtualProtect((LPVOID)FunctionAddr, 4096, oldProtect, &oldProtect);

            return TRUE;
        }
        thunk++;
    }

    return FALSE;



}


void main() 
{   

    Hookit((char*)"Kernel32.dll",(char*)"Sleep", (PROC)HeapSleep);

    while (true)
    {
        printf("\n\n\n[+] Suspend Worker Threads\n");
        SuspendThreads(GetCurrentThreadId());

        Sleep(5000);

        printf("[+] Resume Worked Threads\n\n\n");
        ResumeThreads(GetCurrentThreadId());

    }
    
}