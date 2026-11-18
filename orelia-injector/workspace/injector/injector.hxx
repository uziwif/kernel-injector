namespace injector {
    class c_injector {
    public:
        c_injector( bool reflective_mode ) :
            m_reflective_mode( reflective_mode ) {
        }

        bool map( const char* path_name ) {
            logging::print( encrypt( "Starting payload mapping process" ) );

            auto pe_image = std::make_unique<module::c_module>( );
            if ( !pe_image->load_file( path_name ) ) {
                logging::print( encrypt( "Failed to parse pe headers." ) );
                return false;
            }

            if ( !pe_image->is_dll( ) ) {
                logging::print( encrypt( "Image is not a dll or corrupted PE Headers." ) );
                return false;
            }

            this->m_image_size = pe_image->get_image_size( );
            this->m_image_va = g_driver->allocate_virtual( m_image_size );
            if ( !m_image_va ) {
                logging::print( encrypt( "Failed to allocate virtual memory (status 0x%08X, size 0x%X)." ),
                                g_driver->m_last_error, m_image_size );
                return false;
            }

            auto [image_pa, page_size] = g_driver->translate_linear( m_image_va );
            if ( !image_pa || !page_size ) {
                logging::print( encrypt( "Failed to map virtual memory." ) );
                g_driver->free_virtual( m_image_va );
                return false;
            }

            logging::print( encrypt( "PE allocated at: 0x%llx, Size=0x%x" ), m_image_va, m_image_size );
            logging::print( encrypt( "PE page at: 0x%llx, Size=0x%x" ), image_pa, page_size );

            if ( !pe_image->map_imports( ) ) {
                logging::print( encrypt( "Failed to map imports" ) );
                return false;
            }

            if ( !pe_image->map_delayed_imports( ) ) {
                logging::print( encrypt( "Failed to map imports" ) );
                return false;
            }

            if ( !pe_image->copy_headers( m_image_va ) ) {
                logging::print( encrypt( "Failed to write header" ) );
                return false;
            }

            if ( !pe_image->map_sections( m_image_va ) ) {
                logging::print( encrypt( "Failed to write sections" ) );
                return false;
            }

            //if ( !pe_image->protect_sections( m_image_va ) ) {
            //    logging::print( encrypt( "Failed to protect sections" ) );
            //    return false;
            //}

            if ( !pe_image->relocate( m_image_va ) ) {
                logging::print( encrypt( "Failed to relocate image" ) );
                return false;
            }

            if ( m_reflective_mode ) {
                this->m_entry_point = pe_image->find_export( encrypt( "reflective_loader" ) );
                if ( !m_entry_point ) {
                    logging::print( encrypt( "Failed to get Reflective RVA" ) );
                    return false;
                }
            }
            else {
                this->m_entry_point = pe_image->find_export( encrypt( "DllMain" ) );
                if ( !m_entry_point ) {
                    logging::print( encrypt( "Failed to get DllMain RVA" ) );
                    return false;
                }
            }

            this->m_entry_point += m_image_va;

            {
                unsigned char first[ 16 ]{};
                if ( g_driver->read_memory( m_entry_point, first, sizeof( first ) ) ) {
                    char hex[ 16 * 3 + 1 ]{};
                    for ( int i = 0; i < 16; ++i )
                        std::snprintf( hex + i * 3, 4, "%02X ", first[ i ] );
                    logging::print( encrypt( "Entry bytes: %s" ), hex );
                }
            }
            logging::print( encrypt( "Module preparation completed successfully\n" ) );
            return true;
        }

        bool hook( ) {
            /* The shellcode object owns the candidate list: setup() collects
             * it, run() patches one slot at a time and watches the status
             * word, so a stale legacy RVA or a live-but-wrong API slot costs
             * one 1.5 s probe instead of the whole run. */
            std::unique_ptr<shellcode::c_shellcode> shellcode;
            if ( m_reflective_mode ) {
                reflective::reflective_data_t reflective_data{ };
                reflective_data.m_base_address = g_driver->m_base_address;
                reflective_data.m_dll_base = m_image_va;
                reflective_data.m_dll_size = m_image_size;

                shellcode = std::make_unique<shellcode::c_shellcode>( m_entry_point, reflective_data );
            }
            else {
                shellcode = std::make_unique<shellcode::c_shellcode>( m_entry_point );
                shellcode->set_image_base( m_image_va );
            }

            if ( !shellcode->setup( ) ) {
                logging::print( encrypt( "Failed to setup shellcode." ) );
                shellcode->cleanup( );
                return false;
            }

            if ( shellcode->run( ) ) {
                shellcode->cleanup( );
                return true;
            }

            logging::print( encrypt( "Failed to run shellcode." ) );
            if ( shellcode->initialization_in_progress( ) ) {
                logging::print( encrypt( "Initialization is still in progress. Restart the target before retrying." ) );
                m_image_va = 0;
            }
            shellcode->cleanup( );
            return false;
        }

        void cleanup( ) const {
            if ( m_image_va ) g_driver->free_virtual( m_image_va );
        }

    private:
        std::uint64_t m_image_va = 0;
        std::uint32_t m_image_size = 0;
        std::uint64_t m_entry_point = 0;
        bool m_reflective_mode = false;
    };
}
