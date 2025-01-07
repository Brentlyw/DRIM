# Debug Register Injection Module (DRIM)

## Overview
DRIM is a x64 Windows shellcode injection framework that utilizes unique evasion techniques through debug register manipulation, vectored exception handling, and the Windows Performance Data Helper (PDH) API.

## Technical Details

### Features
- Pseudo-random runtime key generation using system specific & time values
- Debug register manipulation for dynamic API enumeration
- Vectored exception handling for address decryption
- PDH-based PID enumeration
- Entire injection routine uses the undocumented NTDLL.DLL Native API alternatives

### Extras
- Includes payload obfuscator (py script)
- Includes string obfuscator (py script)
- Includes .bin -> char array (py script)
### Architecture Support
- Supports x64 architecture

### To Do
- Implement sleep hook, trampoline for sleep obfuscation / call stack spoofing (90% Completed)


## Detections
[0/38 on KleenScan](https://kleenscan.com/scan_result/2a964980b488ced30f923fc04c19a8a81b6b13ee5d8ae84fc21c7b30b6ebfd47)  
*UPX* [2/38 on KleenScan](https://kleenscan.com/scan_result/4cdd9b456c12bf20e73b23d58e19a5469ba7efffa08f3aa8939cb639b26b955d)
