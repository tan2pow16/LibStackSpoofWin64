# Windows x64 Stack Spoofing Lib

This is a just-4-fun C library that makes stack spoofing a bit easier on x64 Windows.  

## Backstory
A little while ago, I got [this sample](https://www.virustotal.com/gui/file/9cc0de5de977708445e5ce017d6d5d97e00c7749e3a93e8308d493687163af21) from one of my private threat hunting sources. The sample stood out from the rest, as it utilized stack spoofing to mess with anti-malware solutions. I made [a simple analysis](https://github.com/tan2pow16/Malware-Analysis-Write-ups/tree/main/25-02-28-StackSpoof), and later found that the assembly was pulled from an open-source project named [LoudSunRun](https://github.com/susMdT/LoudSunRun).  

I also produced a small C header file to toy with the code. Well, why not turn it into an east-to-use C library? So here it is.  

## Building
I used mingw-w64 to build the project. Put your mingw-w64 environment in `compile.bat`, and it should be able to produce a static object file in the `build/` folder.  

## Usage
To use the stack-spoofing functions in your code, `#include "trampoline.h"` in your C source file(s). It provides the following functions:  

```C
void *stack_spoof_call_api(uint8_t args_cnt, uint64_t api_hash, /* args for the target function */ ...);
void *stack_spoof_call_fptr(uint8_t args_cnt, void *fptr, /* args for the target function */ ...);
```

The first argument is the number of arguments that should be passed into the target function. The value cannot exceed 20. You will have to modify `trampoline-asm.S` should you want to raise the limit.  

The 2nd argument can either be a pointer to the target function (for `stack_spoof_call_fptr`) or a 64-bit hash (`(lib_hash << 32) | func_hash`) of the target Windows API (for `stack_spoof_call_api`). Please beware that the corresponding API library module must be loaded beforehand if you want to use the latter, or the program will crash.  

Both functions simply return what the target function has returned.  

## Demo
A simple shellcode loader is available in the `demo/` folder. Please note that this demo does not come with a build script and there will never be one. I'm not a fan of giving criminals free tools to abuse.  

## Credits
The project uses the following libraries:  
 1. Stack spoofing code modded from [LoudSunRun](https://github.com/susMdT/LoudSunRun)  
 2. API-hashing code modded from [MaldevAcademyLdr](https://github.com/Maldev-Academy/MaldevAcademyLdr.1)  

Special thanks to the authors of these cool projects!  
