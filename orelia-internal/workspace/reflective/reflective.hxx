#include <winternl.h>

enum e_reflective_status : std::uint32_t {
    invalid_parameters = 1,
    mapping_failed = 2,
    dllmain_failed = 3,
    executed_dll_main = 4
};

struct reflective_data_t {
    std::uint64_t m_base_address;
    std::uint32_t m_dll_return;
    std::uint64_t m_dll_base;
    std::size_t m_dll_size;
};

int __strcmp( const char* str1, const char* str2 ) {
    while ( *str1 && *str2 ) {
        if ( *str1 != *str2 ) {
            return static_cast< unsigned char >( *str1 ) - static_cast< unsigned char >( *str2 );
        }
        ++str1;
        ++str2;
    }

    return static_cast< unsigned char >( *str1 ) - static_cast< unsigned char >( *str2 );
}

std::uint64_t get_export( std::uint64_t module_base, const char* export_name ) {
    if ( !module_base || !export_name )
        return NULL;

    IMAGE_DOS_HEADER* dos_header = ( IMAGE_DOS_HEADER* )module_base;
    if ( dos_header->e_magic != IMAGE_DOS_SIGNATURE )
        return NULL;

    IMAGE_NT_HEADERS* nt_headers = ( IMAGE_NT_HEADERS* )( module_base + dos_header->e_lfanew );
    if ( nt_headers->Signature != IMAGE_NT_SIGNATURE )
        return NULL;

    IMAGE_DATA_DIRECTORY* export_directory = &nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
    if ( export_directory->Size == 0 )
        return NULL;

    IMAGE_EXPORT_DIRECTORY* exports = ( IMAGE_EXPORT_DIRECTORY* )( module_base + export_directory->VirtualAddress );
    if ( exports->NumberOfFunctions == 0 ) {
        return 1111;
    }

    DWORD* address_of_functions = ( DWORD* )( module_base + exports->AddressOfFunctions );
    DWORD* address_of_names = ( DWORD* )( module_base + exports->AddressOfNames );
    WORD* address_of_name_ordinals = ( WORD* )( module_base + exports->AddressOfNameOrdinals );

    for ( DWORD i = 0; i < exports->NumberOfNames; i++ ) {
        auto function_name = ( char* )( module_base + address_of_names[ i ] );
        if ( __strcmp( function_name, export_name ) == 0 ) {
            WORD ordinal = address_of_name_ordinals[ i ];
            DWORD function_rva = address_of_functions[ ordinal ];
            return ( std::uint64_t )( module_base + function_rva );
        }
    }

    return exports->NumberOfNames;
}

typedef struct {
    WORD	offset : 12;
    WORD	type : 4;
} image_reloc_t;

bool map_memory_dll( std::uint64_t base_address ) {
    if ( !base_address ) return false;

    auto dos_header = ( IMAGE_DOS_HEADER* )base_address;
    if ( dos_header->e_magic != IMAGE_DOS_SIGNATURE ) return false;

    auto nt_headers = ( IMAGE_NT_HEADERS* )( base_address + dos_header->e_lfanew );
    if ( nt_headers->Signature != IMAGE_NT_SIGNATURE ) return false;

    auto reloc_delta = base_address - nt_headers->OptionalHeader.ImageBase;
    auto reloc_dir = &nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];
    if ( reloc_dir->Size ) {
        auto reloc_block = ( IMAGE_BASE_RELOCATION* )( base_address + reloc_dir->VirtualAddress );

        while ( reloc_block->SizeOfBlock ) {
            auto reloc_va = base_address + reloc_block->VirtualAddress;
            auto reloc_entries = ( reloc_block->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( image_reloc_t );
            auto reloc_entry = ( image_reloc_t* )( ( BYTE* )reloc_block + sizeof( IMAGE_BASE_RELOCATION ) );

            if ( reloc_entries > 0 ) {
                auto first_entry = reloc_entry;
                auto first_offset = first_entry->offset;
                auto first_type = first_entry->type;

                if ( first_type == IMAGE_REL_BASED_DIR64 ) {
                    auto value = *( std::uint64_t* )( reloc_va + first_offset );
                    if ( value >= base_address ) {
                        reloc_block = ( IMAGE_BASE_RELOCATION* )( ( BYTE* )reloc_block + reloc_block->SizeOfBlock );
                        continue;
                    }
                }
                else if ( first_type == IMAGE_REL_BASED_HIGHLOW ) {
                    auto value = *( std::uint32_t* )( reloc_va + first_offset );
                    if ( value >= ( std::uint32_t )base_address ) {
                        reloc_block = ( IMAGE_BASE_RELOCATION* )( ( BYTE* )reloc_block + reloc_block->SizeOfBlock );
                        continue;
                    }
                }
            }

            while ( reloc_entries-- ) {
                if ( reloc_entry->type == IMAGE_REL_BASED_DIR64 )
                    *( std::uint64_t* )( reloc_va + reloc_entry->offset ) += reloc_delta;
                else if ( reloc_entry->type == IMAGE_REL_BASED_HIGHLOW )
                    *( std::uint32_t* )( reloc_va + reloc_entry->offset ) += ( std::uint32_t )reloc_delta;
                else if ( reloc_entry->type == IMAGE_REL_BASED_HIGH )
                    *( std::uint16_t* )( reloc_va + reloc_entry->offset ) += HIWORD( reloc_delta );
                else if ( reloc_entry->type == IMAGE_REL_BASED_LOW )
                    *( std::uint16_t* )( reloc_va + reloc_entry->offset ) += LOWORD( reloc_delta );

                reloc_entry++;
            }

            reloc_block = ( IMAGE_BASE_RELOCATION* )( ( BYTE* )reloc_block + reloc_block->SizeOfBlock );
        }
    }

    auto import_dir = &nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
    if ( import_dir->Size ) {
        auto import_desc = ( IMAGE_IMPORT_DESCRIPTOR* )( base_address + import_dir->VirtualAddress );
        while ( import_desc->Name ) {
            auto dll_name = ( char* )( base_address + import_desc->Name );
            LoadLibraryA( dll_name );
            import_desc++;
        }
    }

    auto delayed_import_dir = &nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT ];
    if ( delayed_import_dir->Size ) {
        auto delayed_desc = ( IMAGE_DELAYLOAD_DESCRIPTOR* )( base_address + delayed_import_dir->VirtualAddress );
        while ( delayed_desc->DllNameRVA ) {
            auto dll_name = ( char* )( base_address + delayed_desc->DllNameRVA );
            LoadLibraryA( dll_name );
            delayed_desc++;
        }
    }

    auto tls_dir = &nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_TLS ];
    if ( tls_dir->Size ) {
        auto tls = ( IMAGE_TLS_DIRECTORY* )( base_address + tls_dir->VirtualAddress );
        if ( tls->AddressOfCallBacks ) {
            auto callback = ( PIMAGE_TLS_CALLBACK* )tls->AddressOfCallBacks;
            while ( *callback ) {
                ( *callback )( ( LPVOID )base_address, DLL_PROCESS_ATTACH, NULL );
                callback++;
            }
        }
    }

    return FlushInstructionCache( ( HANDLE )-1, reinterpret_cast< void* >( base_address ), 0 );
}

extern "C" __declspec( dllexport ) e_reflective_status reflective_loader( reflective_data_t* data ) {
    if ( !data->m_dll_base || !data->m_base_address ) {
        return e_reflective_status::dllmain_failed;
    }

    if ( !map_memory_dll( data->m_dll_base ) ) {
        return e_reflective_status::mapping_failed;
    }

    auto dll_main = get_export( data->m_dll_base, encrypt( "DllMain" ) );
    if ( !dll_main ) {
        return e_reflective_status::dllmain_failed;
    }

    auto dllmain = reinterpret_cast< bool( __stdcall* )( std::uint64_t, std::uint32_t, std::uint64_t ) >( dll_main );
    data->m_dll_return = dllmain( data->m_dll_base, DLL_PROCESS_ATTACH, data->m_base_address );
    return e_reflective_status::executed_dll_main;
}