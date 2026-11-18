#include <dependencies/impl/includes.h>
void* memcpy_t(void* dest, const void* src, unsigned __int64 count)
{
    char* char_dest = (char*)dest;
    char* char_src = (char*)src;
    if ((char_dest <= char_src) || (char_dest >= (char_src + count)))
    {
        while (count > 0)
        {
            *char_dest = *char_src;
            char_dest++;
            char_src++;
            count--;
        }
    }
    else
    {
        char_dest = (char*)dest + count - 1;
        char_src = (char*)src + count - 1;
        while (count > 0)
        {
            *char_dest = *char_src;
            char_dest--;
            char_src--;
            count--;
        }
    }
    return dest;
}

bool LoadDLL(const char* dllPath) {
    HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, nullptr);
    LPVOID fileBuffer = VirtualAlloc(nullptr, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    DWORD bytesRead;
    if (!ReadFile(hFile, fileBuffer, fileSize, &bytesRead, nullptr)) {
        CloseHandle(hFile);
        return false;
    }
    CloseHandle(hFile);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        return false;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)fileBuffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        return false;
    }

    LPVOID imageBase = VirtualAlloc(nullptr, ntHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!imageBase) {
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        return false;
    }

    memcpy_t(imageBase, fileBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        if (section->SizeOfRawData > 0) {
            LPVOID dest = (LPVOID)((BYTE*)imageBase + section->VirtualAddress);
            LPVOID src = (LPVOID)((BYTE*)fileBuffer + section->PointerToRawData);
            memcpy_t(dest, src, section->SizeOfRawData);
        }
    }

    DWORD_PTR delta = (DWORD_PTR)imageBase - ntHeaders->OptionalHeader.ImageBase;
    if (delta != 0) {
        PIMAGE_DATA_DIRECTORY relocDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir->Size > 0) {
            PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)imageBase + relocDir->VirtualAddress);

            while (reloc->VirtualAddress) {
                DWORD numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* relocData = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));

                for (DWORD i = 0; i < numEntries; i++) {
                    int type = relocData[i] >> 12;
                    int offset = relocData[i] & 0xFFF;

                    if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) {
                        DWORD_PTR* patchAddr = (DWORD_PTR*)((BYTE*)imageBase + reloc->VirtualAddress + offset);
                        *patchAddr += delta;
                    }
                }

                reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
            }
        }
    }

    PIMAGE_DATA_DIRECTORY importDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir->Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)imageBase + importDir->VirtualAddress);

        while (importDesc->Name) {
            char* moduleName = (char*)((BYTE*)imageBase + importDesc->Name);
            HMODULE hModule = LoadLibraryA(moduleName);

            if (!hModule) {
                MessageBoxA(nullptr, "Import Failed", "Error", MB_OK);
                return false;
            }

            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)imageBase + importDesc->FirstThunk);
            PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((BYTE*)imageBase + importDesc->OriginalFirstThunk);

            while (thunk->u1.Function) {
                if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) {
                    LPCSTR funcOrdinal = (LPCSTR)IMAGE_ORDINAL(origThunk->u1.Ordinal);
                    thunk->u1.Function = (DWORD_PTR)GetProcAddress(hModule, funcOrdinal);
                }
                else {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)imageBase + origThunk->u1.AddressOfData);
                    thunk->u1.Function = (DWORD_PTR)GetProcAddress(hModule, importByName->Name);
                }

                thunk++;
                origThunk++;
            }

            importDesc++;
        }
    }

    // Call DllMain
    typedef BOOL(WINAPI* DllEntryProc)(HINSTANCE, DWORD, LPVOID);
    DllEntryProc dllEntry = (DllEntryProc)((BYTE*)imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);

    if (dllEntry) {
        dllEntry((HINSTANCE)imageBase, DLL_PROCESS_ATTACH, nullptr);
    }

    VirtualFree(fileBuffer, 0, MEM_RELEASE);

  /*  MessageBoxA(nullptr, "DLL manually mapped successfully!", "Success", MB_OK);*/
    return true;
}

unsigned __stdcall pipe_thread(void*) {
    LoadDLL("C:\\paste.dll");

    return 1;
}
//typedef BOOL( WINAPI* DllMainFn )( HINSTANCE , DWORD , LPVOID );
//
//unsigned __stdcall pipe_thread( void* ) {
//    HMODULE hModule = LoadLibraryA( "C:\\cheat.dll" );
//    if ( !hModule )
//    {
//        MessageBoxA( nullptr , "Failed to load DLL" , "Error" , MB_OK | MB_ICONERROR );
//        return 0;
//    }
//
//    DllMainFn dll_main = ( DllMainFn ) GetProcAddress( hModule , "DllMain" );
//    if ( !dll_main )
//    {
//        MessageBoxA( nullptr , "Failed to find DllMain" , "Error" , MB_OK | MB_ICONERROR );
//        FreeLibrary( hModule );
//        return 0;
//    }
//
//    if ( dll_main( ( HINSTANCE ) hModule , DLL_PROCESS_ATTACH , nullptr ) ) MessageBoxA( nullptr , "DLL injected successfully" , "Success" , MB_OK | MB_ICONINFORMATION );
//	else MessageBoxA( nullptr , "DllMain returned false" , "Error" , MB_OK | MB_ICONERROR );
//
//    //pipe::c_pipe pipe;
//    //if ( !pipe.create( ) ) {
//    //    return 0;
//    //}
//
//    //while ( true ) {
//    //    //if ( !pipe.wait_for_connection( ) ) {
//    //    //    continue;
//    //    //}
//
//    //    //auto cmd = pipe.get_cmd( );
//    //    //if ( cmd.is_completed( ) && cmd.get_magic( ) != pipe::magic_code ) {
//    //    //    continue;
//    //    //}
//
//    //    //switch ( cmd.get_type( ) ) {
//    //    //case pipe::e_command_type::ping_server:
//    //    //{
//    //    //    cmd.set_status( pipe::in_progressive_state );
//    //    //    cmd.set_completed( true );
//    //    //    pipe.send_cmd( cmd );
//    //    //} break;
//
//    //    //case pipe::e_command_type::debug_print:
//    //    //{
//    //    //    if ( cmd.get_data( ).buffer && cmd.get_data( ).size > 0 ) {
//    //    //        OutputDebugStringA( static_cast< const char* >( cmd.get_data( ).buffer ) );
//    //    //    }
//    //    //    cmd.set_status( pipe::in_success_state );
//    //    //    cmd.set_completed( true );
//    //    //    pipe.send_cmd( cmd );
//    //    //} break;
//
//    //    //case pipe::e_command_type::message_box:
//    //    //{
//    //    //    if ( cmd.get_data( ).buffer && cmd.get_data( ).size > 0 ) {
//    //    //        MessageBoxA( NULL, static_cast< const char* >( cmd.get_data( ).buffer ), "Orelia", MB_OK );
//    //    //    }
//    //    //    cmd.set_status( pipe::in_success_state );
//    //    //    cmd.set_completed( true );
//    //    //    pipe.send_cmd( cmd );
//    //    //} break;
//
//    //    //default:
//    //    //{
//    //    //    cmd.set_status( pipe::in_failure_state );
//    //    //    cmd.set_completed( true );
//    //    //    pipe.send_cmd( cmd );
//    //    //} break;
//    //    //}
//    //}
//
//    return 1;
//}
//
extern "C" __declspec( dllexport ) BOOL /*bool_t*/ APIENTRY DllMain(
    std::uint64_t module_base,
    std::uint32_t reason,
    std::uint64_t base_address
) {
    if ( reason == 1 ) {
        if ( !module_base ) {
            return FALSE;
        }

        auto handle = _beginthreadex( 0, 0, pipe_thread, 0, 0, 0 );
        CloseHandle( reinterpret_cast< HANDLE >( handle ) );
    }

    return true;
}