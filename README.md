# Debug Register Injection Module (DRIM)

## Overview
DRIM is a x64 Windows code injection framework that utilizes CPU debug registers for function resolution/enumeration and code execution. It implements unique evasion techniques through debug register manipulation, vectored exception handling, and the Windows Performance Data Helper (PDH) API.

## Technical Details

### Core Components
- Runtime key generation using system-specific & time values
- Debug register manipulation for dynamic API enumeration
- Vectored exception handling for address decryption
- PDH-based PID enumeration
- Undocumented NTDLL.DLL Native API injection routine

## Implementation

### Function Resolution
DRIM resolves functions by encrypting legitimate addresses and storing them in CPU debug registers. The resolution process uses vectored exception handling to decrypt addresses during execution. This method bypasses common API hooking and monitoring.

### Target PID Resolution
The target's PID resolution is performed through PDH queries rather than conventional process enumeration or snapshots. This approach provides enhanced evasion by avoiding commonly signatured code, and monitored Windows APIs.

### Injection Method
The injection routine utilizes NT native functions exclusively:
```c
NtAllocateVirtualMemory  // Memory allocation
NtWriteVirtualMemory     // Code writing
NtProtectVirtualMemory   // Permission modification
NtOpenProcess            // Open handle
RtlCreateUserThread      // Thread creation
```

### Architecture Support
- Supports x64 architecture
- Architecture-specific handling for stack pointer access

## Technical Notes

### API String Obfuscation
Function names and DLL strings are obfuscated through arithmetic operations. The python file included performs string->obfuscated char array:
```c
char g_dll[] = {(((224-4)<<1)>>2), ..}; // "ntdll.dll"
```

### Debug Register Configuration
Debug registers are configured through thread context manipulation:
```c
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_ALL;
```

### Exception Handling
Vectored exception handler processes EXCEPTION_SINGLE_STEP exceptions for address resolution:
```c
LONG WINAPI VectoredHandler(PEXCEPTION_POINTERS pExceptionInfo)
```

## Usage Example

```c
DWORD explorerPID = FindExplorerPID();
if (!explorerPID) return 1;

InjectBreakpoint(explorerPID, NtAllocateVirtualMemoryFunc, 
    NtWriteVirtualMemoryFunc, NtProtectVirtualMemoryFunc, 
    RtlCreateUserThreadFunc);
```


## Detections
0/38 on KleenScan
