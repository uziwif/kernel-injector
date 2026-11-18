#include <chrono>
#include <ctime>
#include <vector>
#include <Windows.h>
#include <tlhelp32.h>
#include <fstream>
#include <vector>
#include <winternl.h>
#include <cstdint>
#include <DbgHelp.h>
#include <thread>
#include <mutex>
#include <map>
#include <algorithm>
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "ntdll.lib")

/* Target defaults to the shipping title; ORELIA_TARGET overrides it so the
 * same binary can drive the scratch host without a rebuild. */
static inline const wchar_t* target_process_name( ) {
    static wchar_t name[ 64 ] = L"ROB RUN.exe";
    static bool resolved = false;
    if ( !resolved ) {
        resolved = true;
        GetEnvironmentVariableW( L"ORELIA_TARGET" , name , 64 );
    }
    return name;
}
#define target_process target_process_name( )

#include <dependencies/skcrypt/skcrypter.h>
#include <workspace/logger/logger.hxx>
#include <workspace/exception/exception.hxx>

#include <impl/ia32/ia32.h>
#include <impl/wdk/wdk.h>
#include <workspace/driver/driver.hxx>
auto g_driver = new driver::c_driver;

#include <impl/asmjit/core.h>
#include <impl/asmjit/a64.h>
#include <impl/asmjit/x86.h>

#include <workspace/injector/module/apiset/apiset.hxx>
#include <workspace/injector/module/resolver/resolver.hxx>
#include <workspace/injector/module/module.hxx>

#include <workspace/injector/shellcode/shellcode.h>
#include <workspace/injector/shellcode/reflective/reflective.h>
#include <workspace/injector/shellcode/compiler/compiler.hxx>
#include <workspace/injector/shellcode/internals/internals.hxx>
#include <workspace/injector/injector.hxx>