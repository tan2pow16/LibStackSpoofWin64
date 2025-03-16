@echo off

setlocal

set MINGW_HOME=D:\mingw81
set PATH=%PATH%;%MINGW_HOME%\bin;%MINGW_HOME%\libexec\gcc\x86_64-w64-mingw32\8.1.0;%MINGW_HOME%\opt\bin;%MINGW_HOME%\x86_64-w64-mingw32\bin

set RETURN_DIR=%CD%

cd /D %~dp0

:: Un-comment this to update the API hashes.
::node utils\hashgen.js

gcc -S -Os -o cache\api-hashing.S src\api-hashing.c
gcc -S -Os -o cache\camouflage.S src\camouflage.c
gcc -S -Os -o cache\trampoline.S src\trampoline.c

as -o cache\trampoline-asm.o src\trampoline-asm.S
as -o cache\stackspoof.o src\stackspoof.S
as -o cache\api-hashing.o cache\api-hashing.S
as -o cache\camouflage.o cache\camouflage.S
as -o cache\trampoline.o  cache\trampoline.S

ld -r -o build\libstackspoofwin64.o cache\api-hashing.o cache\stackspoof.o cache\camouflage.o cache\trampoline.o cache\trampoline-asm.o

cd /D %RETURN_DIR%

endlocal

pause
