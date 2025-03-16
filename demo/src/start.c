#include <windows.h>

int __wchar_main__(int argc, WCHAR *const argvw[]);

int __start__()
{
  int argc;
  LPWSTR *argvw;

  argvw = CommandLineToArgvW(GetCommandLineW(), &argc);
  if(argc <= 0)
  {
    // That's really bad. Oof.
    return GetLastError();
  }

  return __wchar_main__(argc, argvw);
}
