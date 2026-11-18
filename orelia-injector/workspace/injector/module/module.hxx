#include <map>

namespace module {
    class c_module {
    public:
        bool load_file( const std::string& file_path ) {
            std::ifstream file( file_path, std::ios::binary | std::ios::ate );
            if ( !file.is_open( ) ) {
                logging::print( encrypt( "Failed to open file: %s" ), file_path.c_str( ) );
                return false;
            }

            const auto file_size = file.tellg( );
            if ( file_size <= 0 ) {
                logging::print( encrypt( "Invalid file size: %s" ), file_path.c_str( ) );
                return false;
            }

            m_target_image.resize( static_cast< size_t >( file_size ) );

            file.seekg( 0, std::ios::beg );
            if ( !file.read( reinterpret_cast< char* >( m_target_image.data( ) ), file_size ) ) {
                logging::print( encrypt( "Failed to read file: %s" ), file_path.c_str( ) );
                m_target_image.clear( );
                return false;
            }

            m_dos_header = reinterpret_cast< PIMAGE_DOS_HEADER >( m_target_image.data( ) );
            if ( m_dos_header->e_magic != IMAGE_DOS_SIGNATURE ) {
                logging::print( encrypt( "Invalid DOS signature in: %s" ), file_path.c_str( ) );
                m_target_image.clear( );
                return false;
            }

            m_nt_headers = reinterpret_cast< PIMAGE_NT_HEADERS >(
                m_target_image.data( ) + m_dos_header->e_lfanew
                );
            if ( m_nt_headers->Signature != IMAGE_NT_SIGNATURE ) {
                logging::print( encrypt( "Invalid NT headers in: %s" ), file_path.c_str( ) );
                m_target_image.clear( );
                return false;
            }

            if ( m_nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ) {
                logging::print( encrypt( "The loaded file is not supported." ) );
                m_target_image.clear( );
                return false;
            }

            m_section_header = reinterpret_cast< IMAGE_SECTION_HEADER* >(
                ( std::uintptr_t )( &m_nt_headers->OptionalHeader ) + m_nt_headers->FileHeader.SizeOfOptionalHeader
                );

            m_optional_header = m_nt_headers->OptionalHeader;

            logging::print( encrypt( "Successfully loaded file: %s (Size: 0x%llX)" ),
                file_path.c_str( ), file_size );
            return true;
        }

        std::uint32_t get_image_size( ) const {
            return m_optional_header.SizeOfImage;
        }

        std::uint64_t get_entry_point( ) const {
            return m_optional_header.AddressOfEntryPoint;
        }

        bool is_dll( ) const {
            return ( m_nt_headers->FileHeader.Characteristics & IMAGE_FILE_DLL ) != 0;
        }

        std::uint64_t find_export( const char* export_name ) {
            auto export_dir = get_directory( IMAGE_DIRECTORY_ENTRY_EXPORT );
            if ( export_dir->VirtualAddress && export_dir->Size ) {
                auto export_directory = rva_to_va<PIMAGE_EXPORT_DIRECTORY>( export_dir->VirtualAddress );
                if ( export_directory ) {
                    auto functions = rva_to_va<DWORD*>( export_directory->AddressOfFunctions );
                    auto names = rva_to_va<DWORD*>( export_directory->AddressOfNames );
                    auto ordinals = rva_to_va<WORD*>( export_directory->AddressOfNameOrdinals );

                    if ( functions && names && ordinals ) {
                        for ( DWORD i = 0; i < export_directory->NumberOfNames; i++ ) {
                            auto name = rva_to_va<const char*>( names[ i ] );
                            if ( !name ) continue;

                            if ( !strcmp( name, export_name ) ) {
                                auto ordinal = ordinals[ i ];
                                return functions[ ordinal ];
                            }
                        }
                    }
                }
            }

            return 0;
        }

        bool map_imports( ) {            auto import_dir = &m_nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
            if ( !import_dir->VirtualAddress || !import_dir->Size ) {
                logging::print( encrypt( "No imports to resolve" ) );
                return true;
            }

            auto import_desc = rva_to_va<PIMAGE_IMPORT_DESCRIPTOR>( import_dir->VirtualAddress );
            if ( !import_desc ) {
                logging::print( encrypt( "Invalid import descriptor" ) );
                return false;
            }

            size_t imports = 0;
            size_t modules = 0;

            while ( import_desc->Name ) {
                modules++;
                auto module_name = rva_to_va<const char*>( import_desc->Name );
                if ( !module_name ) {
                    logging::print( encrypt( "Invalid module name" ) );
                    return false;
                }

                auto resolved_name = resolver::resolve_module_name( module_name );
                if ( resolved_name.empty( ) ) {
                    logging::print( encrypt( "Invalid module name" ) );
                    return false;
                }

                auto module_handle = LoadLibraryW( resolved_name.c_str( ) );
                if ( !module_handle ) {
                    logging::print( encrypt( "LoadLibrary failed for %ls: %d" ),
                        resolved_name.c_str( ), GetLastError( ) );
                    return false;
                }

                auto module_base = g_driver->get_process_module( resolved_name.c_str( ) );
                if ( !module_base ) {
                    /* Writing this process's GetProcAddress value would leave a
                       dangling address in the target IAT and kill it on first call. */
                    logging::print( encrypt( "Target is missing %ls; aborting before sections are written" ),
                        resolved_name.c_str( ) );
                    FreeLibrary( module_handle );
                    return false;
                }
                logging::print( encrypt( "Import module %-24ls local 0x%llx remote 0x%llx" ),
                    resolved_name.c_str( ),
                    ( unsigned long long )( std::uintptr_t )module_handle,
                    ( unsigned long long )module_base );

                auto thunk_data = rva_to_va<PIMAGE_THUNK_DATA64>( import_desc->FirstThunk );
                auto original_thunk = import_desc->OriginalFirstThunk ?
                    rva_to_va<PIMAGE_THUNK_DATA64>( import_desc->OriginalFirstThunk ) :
                    thunk_data;

                for ( size_t i = 0; original_thunk[ i ].u1.AddressOfData != 0; i++ ) {
                    imports++;

                    uintptr_t func_addr = 0;
                    if ( IMAGE_SNAP_BY_ORDINAL64( original_thunk[ i ].u1.Ordinal ) ) {
                        WORD ordinal = IMAGE_ORDINAL64( original_thunk[ i ].u1.Ordinal );
                        auto func_name = reinterpret_cast< const char* >( static_cast< uintptr_t >( ordinal ) );

                        func_addr = ( uintptr_t )GetProcAddress( module_handle, ( LPCSTR )( ULONG_PTR )ordinal );
                        if ( !func_addr ) {
                            logging::print( encrypt( "GetProcAddress failed for ordinal %u: %d" ),
                                ordinal, GetLastError( ) );
                            FreeLibrary( module_handle );
                            return false;
                        }
                    }
                    else {
                        auto import_by_name = rva_to_va<PIMAGE_IMPORT_BY_NAME>( original_thunk[ i ].u1.AddressOfData );
                        if ( !import_by_name ) {
                            logging::print( encrypt( "Invalid import by name" ) );
                            FreeLibrary( module_handle );
                            return false;
                        }

                        auto func_name = import_by_name->Name;
                        func_addr = ( uintptr_t )GetProcAddress( module_handle, func_name );
                        if ( !func_addr ) {
                            logging::print( encrypt( "GetProcAddress failed for %s: %d" ),
                                func_name, GetLastError( ) );
                            FreeLibrary( module_handle );
                            return false;
                        }
                    }

                    thunk_data[ i ].u1.Function = rebase_import( resolved_name.c_str( ), module_handle, func_addr );
                }

                FreeLibrary( module_handle );
                import_desc++;
            }

            logging::print( encrypt( "Processed %zu imports from %zu modules" ), imports, modules );
            return true;
        }

        bool map_delayed_imports( ) {
            auto delayed_import_dir = get_directory( IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT );
            if ( !delayed_import_dir->VirtualAddress || !delayed_import_dir->Size ) {
                logging::print( encrypt( "No delayed imports to resolve" ) );
                return true;
            }

            auto delayed_desc = rva_to_va<PIMAGE_DELAYLOAD_DESCRIPTOR>( delayed_import_dir->VirtualAddress );
            if ( !delayed_desc ) {
                logging::print( encrypt( "Invalid delayed import descriptor" ) );
                return false;
            }

            size_t modules = 0;
            size_t imports = 0;

            while ( delayed_desc->DllNameRVA != 0 ) {
                modules++;

                if ( !( delayed_desc->Attributes.AllAttributes & 0x1 ) ) {
                    logging::print( encrypt( "Delayed import descriptor not RVA-based" ) );
                    return false;
                }

                auto dll_name = rva_to_va<const char*>( delayed_desc->DllNameRVA );
                if ( !dll_name ) {
                    logging::print( encrypt( "Invalid delayed import DLL name" ) );
                    return false;
                }

                auto resolved_name = resolver::resolve_module_name( dll_name );
                if ( resolved_name.empty( ) ) {
                    logging::print( encrypt( "Failed to resolve module name for delayed import: %s" ), dll_name );
                    return false;
                }

                auto module_handle = LoadLibraryW( resolved_name.c_str( ) );
                if ( !module_handle ) {
                    logging::print( encrypt( "LoadLibrary failed for delayed import %ls: %d" ), resolved_name.c_str( ), GetLastError( ) );
                    return false;
                }

                if ( !g_driver->get_process_module( resolved_name.c_str( ) ) ) {
                    logging::print( encrypt( "Target is missing delayed-import module %ls" ), resolved_name.c_str( ) );
                    FreeLibrary( module_handle );
                    return false;
                }

                auto name_table = rva_to_va<PIMAGE_THUNK_DATA64>( delayed_desc->ImportNameTableRVA );
                auto address_table = rva_to_va<PIMAGE_THUNK_DATA64>( delayed_desc->ImportAddressTableRVA );
                if ( !name_table || !address_table ) {
                    logging::print( encrypt( "Invalid INT or IAT in delayed import" ) );
                    FreeLibrary( module_handle );
                    return false;
                }

                for ( size_t i = 0; name_table[ i ].u1.Ordinal != 0; i++ ) {
                    imports++;

                    uint64_t func_addr = 0;
                    if ( IMAGE_SNAP_BY_ORDINAL64( name_table[ i ].u1.Ordinal ) ) {
                        WORD ordinal = IMAGE_ORDINAL64( name_table[ i ].u1.Ordinal );
                        func_addr = ( uint64_t )GetProcAddress( module_handle, ( LPCSTR )ordinal );
                        if ( !func_addr ) {
                            logging::print( encrypt( "Failed to resolve ordinal %u in %s: %d" ), ordinal, dll_name, GetLastError( ) );
                            FreeLibrary( module_handle );
                            return false;
                        }
                    }
                    else {
                        auto import_by_name = rva_to_va<PIMAGE_IMPORT_BY_NAME>( name_table[ i ].u1.AddressOfData );
                        if ( !import_by_name ) {
                            logging::print( encrypt( "Invalid import by name in delayed import" ) );
                            FreeLibrary( module_handle );
                            return false;
                        }
                        const char* func_name = import_by_name->Name;
                        func_addr = ( uint64_t )GetProcAddress( module_handle, func_name );
                        if ( !func_addr ) {
                            logging::print( encrypt( "Failed to resolve %s in %s: %d" ), func_name, dll_name, GetLastError( ) );
                            FreeLibrary( module_handle );
                            return false;
                        }
                    }

                    address_table[ i ].u1.Function = rebase_import( resolved_name.c_str( ), module_handle, func_addr );
                }

                FreeLibrary( module_handle );
                delayed_desc++;
            }

            logging::print( encrypt( "Mapped %zu delayed imports from %zu modules" ), imports, modules );
            return true;
        }

        //bool protect_sections( std::uint64_t image_base ) {
        //    for ( WORD i = 0; i < m_nt_headers->FileHeader.NumberOfSections; i++ ) {
        //        auto& section = m_section_header[ i ];
        //        auto executable = ( section.Characteristics & IMAGE_SCN_MEM_EXECUTE ) != 0;
        //        auto readable = ( section.Characteristics & IMAGE_SCN_MEM_READ ) != 0;
        //        auto writable = ( section.Characteristics & IMAGE_SCN_MEM_WRITE ) != 0;

        //        std::uint32_t protect = 0;
        //        if ( executable ) {
        //            protect = writable ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        //        }
        //        else {
        //            protect = writable ? PAGE_READWRITE : PAGE_READONLY;
        //        }

        //        auto size = section.Misc.VirtualSize;
        //        auto section_va = image_base + section.VirtualAddress;
        //        if ( !g_driver->protect_virtual( section_va, size, protect ) ) {
        //            logging::print( encrypt( "Failed to protect section %s" ), section.Name );
        //            return false;
        //        }
        //    }
        //    return true;
        //}

        std::vector<std::uint64_t> get_tls_callbacks( ) {
            std::vector<std::uint64_t> callbacks;
            auto tls_dir = get_directory( IMAGE_DIRECTORY_ENTRY_TLS );
            if ( !tls_dir->VirtualAddress || !tls_dir->Size )
                return callbacks;

            auto tls_directory = rva_to_va<PIMAGE_TLS_DIRECTORY64>( tls_dir->VirtualAddress );
            if ( !tls_directory || !tls_directory->AddressOfCallBacks )
                return callbacks;

            auto callback_array = rva_to_va<PIMAGE_TLS_CALLBACK*>( tls_directory->AddressOfCallBacks );
            for ( size_t i = 0; callback_array[ i ] != nullptr; i++ ) {
                callbacks.push_back( reinterpret_cast< std::uint64_t >( callback_array[ i ] ) );
            }

            return callbacks;
        }

        bool map_sections( std::uint64_t new_image_base ) {
            size_t total_bytes_written = 0;

            for ( auto i = 0u; i < m_nt_headers->FileHeader.NumberOfSections; i++ ) {
                const auto& section = m_section_header[ i ];
                if ( !section.VirtualAddress || !section.SizeOfRawData ) {
                    logging::print( encrypt( "Skipping section %s - Invalid parameters" ), section.Name );
                    continue;
                }

                auto section_va = new_image_base + section.VirtualAddress;
                if ( !section_va ) {
                    logging::print( encrypt( "Invalid section found at: %s" ), section.Name );
                    continue;
                }

                if ( !g_driver->write_memory(
                    section_va,
                    reinterpret_cast< void* >( m_target_image.data( ) + section.PointerToRawData ),
                    section.SizeOfRawData ) ) {
                    logging::print( encrypt( "Failed to write section %s" ), section.Name );
                    return false;
                }

                total_bytes_written += section.SizeOfRawData;
                logging::print( encrypt( "Wrote section %-8s (0x%p -> 0x%p)" ),
                    section.Name, m_target_image.data( ) + section.PointerToRawData, section_va );
            }

            return true;
        }

        bool relocate( std::uint64_t new_image_base ) {
            auto reloc_dir = get_directory( IMAGE_DIRECTORY_ENTRY_BASERELOC );
            if ( !reloc_dir->VirtualAddress || !reloc_dir->Size ) {
                logging::print( encrypt( "No relocations needed" ) );
                return true;
            }

            auto delta = new_image_base - m_optional_header.ImageBase;
            if ( delta == 0 ) {
                logging::print( encrypt( "No relocation needed - Image loaded at preferred base address" ) );
                return true;
            }

            auto reloc_block = rva_to_va<PIMAGE_BASE_RELOCATION>( reloc_dir->VirtualAddress );
            auto reloc_end = reinterpret_cast< char* >( reloc_block ) + reloc_dir->Size;

            int block_count = 0;
            int reloc_count = 0;

            while ( reloc_block && reloc_block->VirtualAddress &&
                reinterpret_cast< char* >( reloc_block ) < reloc_end ) {

                block_count++;
                auto entry_count = ( reloc_block->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( WORD );
                auto entries = reinterpret_cast< WORD* >( reloc_block + 1 );

                for ( size_t i = 0; i < entry_count; i++ ) {
                    auto type = entries[ i ] >> 12;
                    auto offset = entries[ i ] & 0xFFF;
                    auto address = new_image_base + reloc_block->VirtualAddress + offset;

                    switch ( type ) {
                    case IMAGE_REL_BASED_ABSOLUTE:
                        break;

                    case IMAGE_REL_BASED_HIGH:
                    {
                        std::uint16_t value;
                        g_driver->read_memory( address, &value, sizeof( value ) );
                        value += static_cast< std::uint16_t >( ( delta >> 16 ) & 0xFFFF );
                        g_driver->write_memory( address, &value, sizeof( value ) );
                    }
                    break;

                    case IMAGE_REL_BASED_LOW:
                    {
                        std::uint16_t value;
                        g_driver->read_memory( address, &value, sizeof( value ) );
                        value += static_cast< std::uint16_t >( delta & 0xFFFF );
                        g_driver->write_memory( address, &value, sizeof( value ) );
                    }
                    break;

                    case IMAGE_REL_BASED_HIGHLOW:
                    {
                        std::uint32_t value;
                        g_driver->read_memory( address, &value, sizeof( value ) );
                        value += static_cast< std::uint32_t >( delta );
                        g_driver->write_memory( address, &value, sizeof( value ) );
                    }
                    break;

                    case IMAGE_REL_BASED_HIGHADJ:
                    {
                        std::uint16_t high_value;
                        g_driver->read_memory( address, &high_value, sizeof( high_value ) );

                        i++;
                        std::uint16_t low_value = entries[ i ];

                        std::uint32_t value = ( high_value << 16 ) | low_value;
                        value += static_cast< std::uint32_t >( delta );
                        value += 0x8000;

                        std::uint16_t new_high = static_cast< std::uint16_t >( value >> 16 );
                        g_driver->write_memory( address, &new_high, sizeof( new_high ) );
                    }
                    break;

                    case IMAGE_REL_BASED_DIR64: {
                        std::uint64_t value;
                        g_driver->read_memory( address, &value, sizeof( value ) );
                        value += delta;
                        g_driver->write_memory( address, &value, sizeof( value ) );
                    } break;

                    case IMAGE_REL_BASED_MIPS_JMPADDR:
                        logging::print( encrypt( "Warning: Unsupported relocation type IMAGE_REL_BASED_MIPS_JMPADDR" ) );
                        break;

                    case IMAGE_REL_BASED_MIPS_JMPADDR16:
                        logging::print( encrypt( "Warning: Unsupported relocation type IMAGE_REL_BASED_MIPS_JMPADDR16" ) );
                        break;

                    case IMAGE_REL_BASED_THUMB_MOV32:
                        logging::print( encrypt( "Warning: Unsupported relocation type IMAGE_REL_BASED_THUMB_MOV32" ) );
                        break;

                    default:
                        logging::print( encrypt( "Warning: Unknown relocation type %d" ), type );
                        break;
                    }

                    if ( type != IMAGE_REL_BASED_ABSOLUTE )
                        reloc_count++;
                }

                reloc_block = reinterpret_cast< PIMAGE_BASE_RELOCATION >(
                    reinterpret_cast< char* >( reloc_block ) + reloc_block->SizeOfBlock );
            }

            logging::print( encrypt( "Processed %d relocations" ), reloc_count );
            return true;
        }

        bool copy_headers( std::uintptr_t image_base ) {
            return g_driver->write_memory(
                image_base,
                m_target_image.data( ),
                m_optional_header.SizeOfHeaders
            );
        }

        bool copy_image( std::uintptr_t image_base ) {
            return g_driver->write_memory(
                image_base,
                m_target_image.data( ),
                m_optional_header.SizeOfImage
            );
        }

        std::vector<uint8_t> get_target_image( ) {
            return m_target_image;
        }

        /* GetProcAddress returns an address in this process's address space; the target may have loaded the
           same module at a different base, so rebase by the delta when the address lands inside the local image. */
        std::uintptr_t rebase_import( const wchar_t* module_name , HMODULE local_module , std::uintptr_t local_addr ) {
            if ( !local_module || !local_addr ) {
                return local_addr;
            }

            const auto* dos = reinterpret_cast< const IMAGE_DOS_HEADER* >( local_module );
            if ( dos->e_magic != IMAGE_DOS_SIGNATURE ) {
                return local_addr;
            }

            const auto* nt = reinterpret_cast< const IMAGE_NT_HEADERS64* >(
                reinterpret_cast< const std::uint8_t* >( local_module ) + dos->e_lfanew );
            if ( nt->Signature != IMAGE_NT_SIGNATURE ) {
                return local_addr;
            }

            const auto local_base = reinterpret_cast< std::uintptr_t >( local_module );
            const auto image_size = static_cast< std::uintptr_t >( nt->OptionalHeader.SizeOfImage );
            if ( local_addr < local_base || local_addr >= local_base + image_size ) {
                return local_addr;
            }

            const auto remote_base = g_driver->get_process_module( module_name );
            if ( !remote_base ) {
                return local_addr;
            }

            return remote_base + ( local_addr - local_base );
        }

    private:
        PIMAGE_DOS_HEADER m_dos_header = nullptr;
        PIMAGE_NT_HEADERS64 m_nt_headers = nullptr;
        PIMAGE_SECTION_HEADER m_section_header = nullptr;
        IMAGE_OPTIONAL_HEADER64 m_optional_header{ };
        std::vector<uint8_t> m_target_image;
        size_t m_total_size = 0;

        IMAGE_SECTION_HEADER* find_section( const char* name ) {
            for ( WORD i = 0; i < m_nt_headers->FileHeader.NumberOfSections; i++ ) {
                auto& section = m_section_header[ i ];

                if ( memcmp( section.Name, name, strlen( name ) ) == 0 ) {
                    logging::print( encrypt( "Found section %s at index %d" ), name, i );
                    logging::print( encrypt( "Section details - VA: 0x%x, Size: 0x%x" ),
                        section.VirtualAddress,
                        section.SizeOfRawData );
                    return &m_section_header[ i ];
                }
            }

            logging::print( encrypt( "Section %s not found" ), name );
            return nullptr;
        }

        template <typename resut, typename type>
        resut rva_to_va( type rva ) {
            auto first_section = m_section_header;
            for ( auto section = first_section; section < first_section + m_nt_headers->FileHeader.NumberOfSections; section++ ) {
                if ( rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize )
                    return reinterpret_cast< resut >( m_target_image.data( ) + section->PointerToRawData + rva - section->VirtualAddress );
            }
            return reinterpret_cast< resut >( nullptr );
        }

        IMAGE_DATA_DIRECTORY* get_directory( int directory_index ) {
            if ( directory_index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES )
                return nullptr;

            return &m_nt_headers->OptionalHeader.DataDirectory[ directory_index ];
        }
    };
}