#define NT_SUCCESS(Status) (((nt_status_t)(Status)) >= 0)
namespace handler {
    nt_status_t read_memory( user::s_command_data* input_data ) {
        auto find_min = [ input_data ] ( std::size_t size ) {
            return ( size < ( input_data->m_size ) ? ( size ) : ( input_data->m_size ) );
            };

        auto physical_address = mm::g_paging.translate( input_data->m_address );
        if ( !physical_address ) {
            return nt_status_t::unsuccessful;
        }

        auto final_size = find_min( mm::paging::page_4kb_size - ( physical_address & mm::paging::page_4kb_mask ) );
        auto result = mm::phys::read_direct(
            physical_address ,
            input_data->m_buffer ,
            final_size
        );

        return result ? nt_status_t::success : nt_status_t::unsuccessful;
    }

    nt_status_t write_memory( user::s_command_data* input_data ) {
        auto find_min = [ input_data ] ( std::size_t size ) {
            return ( size < ( input_data->m_size ) ? ( size ) : ( input_data->m_size ) );
            };

        auto physical_address = mm::g_paging.translate( input_data->m_address );
        if ( !physical_address ) {
            return nt_status_t::unsuccessful;
        }

        auto final_size = find_min( mm::paging::page_4kb_size - ( physical_address & mm::paging::page_4kb_mask ) );
        auto result = mm::phys::write_region(
            physical_address ,
            input_data->m_buffer ,
            final_size
        );

        return result ? nt_status_t::success : nt_status_t::access_violation;
    }

    nt_status_t translate_linear( user::s_command_data* input_data ) {
        std::uint32_t page_size = 0;
        input_data->m_address2 = mm::g_paging.translate( input_data->m_address , &page_size );
        input_data->m_size = static_cast< std::size_t >( page_size );
        return input_data->m_address2 ? nt_status_t::success : nt_status_t::unsuccessful;
    }

    nt_status_t map_process_pte( user::s_command_data* input_data ) {
        kapc_state_t state{};

        nt::m_attach_process( input_data->m_process , &state );

        if ( !mm::g_paging.map_process_pte( input_data->m_address ) ) {
            nt::m_detach_process( &state );
            return nt_status_t::access_violation;
        }

        nt::m_detach_process( &state );
        return input_data->m_address ? nt_status_t::success : nt_status_t::unsuccessful;
    }

    nt_status_t protect_virtual( user::s_command_data* input_data ) {
        kapc_state_t state{};
        nt::m_attach_process( input_data->m_process , &state );

        size_t size = input_data->m_size;
        void* base_address = reinterpret_cast< void* >( input_data->m_address );
        std::uint32_t old_protection = 0;

        nt_status_t status = nt::zw_protect_virtual_memory(
            input_data->m_process ,
            &base_address ,
            &size ,
            input_data->m_new_protection ,
            &old_protection
        );

        nt::m_detach_process( &state );

        if ( !nt::nt_success( status ) ) {
            return nt_status_t::unsuccessful;
        }

        input_data->m_new_protection = old_protection;
        return input_data->m_address ? nt_status_t::success : nt_status_t::unsuccessful;
    }

    nt_status_t allocate_virtual( user::s_command_data* input_data ) {
        if ( !input_data || !input_data->m_pid || !input_data->m_size ) {
            nt::dbg_print( "[allocate_virtual] Invalid input parameters\n" );
            return nt_status_t::invalid_parameter;
        }

        nt::dbg_print( "[allocate_virtual] Starting allocation for PID %u, size: 0x%llx\n" , 
                      input_data->m_pid, input_data->m_size );

        eprocess_t* process = nt::ps_lookup_process_by_process_id( input_data->m_pid );
        if ( !process ) {
            nt::dbg_print( "[allocate_virtual] Failed to find PEPROCESS for PID %u\n" , input_data->m_pid );
            return nt_status_t::unsuccessful;
        }

        kapc_state_t state{};
        nt::m_attach_process( process, &state );

        client_id_t client_id = {};
        client_id.m_unique_process = reinterpret_cast< void* >( static_cast< std::uintptr_t >( input_data->m_pid ) );

        object_attributes_t object_attributes = {};
        nt::init_object_attributes( &object_attributes, nullptr, 0, nullptr, nullptr );

        void* process_handle = nullptr;
        nt_status_t status = nt::zw_open_process(
            &process_handle,
            0x1FFFFF,
            &object_attributes,
            &client_id
        );

        if ( !NT_SUCCESS( status ) || !process_handle ) {
            nt::dbg_print( "[allocate_virtual] ZwOpenProcess failed: 0x%X\n" , status );
            nt::m_detach_process( &state );
            return nt_status_t::unsuccessful;
        }

        nt::dbg_print( "[allocate_virtual] Successfully opened process handle: 0x%p\n" , process_handle );

        void* base_address = nullptr;
        std::size_t region_size = input_data->m_size;

        nt::dbg_print( "[allocate_virtual] Calling ZwAllocateVirtualMemory, size: 0x%llx\n" , region_size );

        status = nt::zw_allocate_virtual_memory(
            process_handle,
            &base_address,
            0,                    // ZeroBits
            &region_size,
            0x00001000 | 0x00002000,  // MEM_COMMIT | MEM_RESERVE
            0x40                  // PAGE_EXECUTE_READWRITE
        );

        if ( !NT_SUCCESS( status ) ) {
            nt::dbg_print( "[allocate_virtual] ZwAllocateVirtualMemory failed: 0x%X\n" , status );
            nt::zw_close( process_handle );
            nt::m_detach_process( &state );
            return status;
        }

        nt::dbg_print( "[allocate_virtual] Successfully allocated memory at: 0x%p, size: 0x%llx\n" , 
                      base_address, region_size );

        nt::zero_memory( base_address, region_size );

        if ( !mm::g_paging.map_process_pte( reinterpret_cast< std::uintptr_t >( base_address ) ) ) {
            nt::dbg_print( "[allocate_virtual] Failed to map PTE for address: 0x%p\n" , base_address );
            std::size_t free_size = region_size;
            nt::zw_free_virtual_memory( process_handle, &base_address, &free_size, 0x8000 );
            nt::zw_close( process_handle );
            nt::m_detach_process( &state );
            return nt_status_t::access_violation;
        }

        input_data->m_address = reinterpret_cast< std::uintptr_t >( base_address );
        input_data->m_size = region_size;

        nt::dbg_print( "[allocate_virtual] Allocation completed successfully at: 0x%llx\n" , input_data->m_address );

        nt::zw_close( process_handle );
        nt::m_detach_process( &state );
        return nt_status_t::success;
    }

    nt_status_t free_virtual( user::s_command_data* input_data ) {
        void* base = reinterpret_cast< void* >( input_data->m_address );
        std::size_t size = input_data->m_size;

        nt_status_t status = nt::zw_free_virtual_memory(
            input_data->m_process ,
            &base ,
            &size ,
            0x8000 // MEM_RELEASE
        );

        if ( !nt_status_t::success( status ) ) {
            return nt_status_t::unsuccessful;
        }

        return nt_status_t::success;
    }

    nt_status_t map_physical( user::s_command_data* input_data ) {
        if ( !input_data->m_address || !input_data->m_size ) {
            return nt_status_t::invalid_parameter;
        }

        auto aligned_phys = mm::g_paging.page_align( input_data->m_address );
        auto page_offset = input_data->m_address - aligned_phys;

        auto total_size = mm::g_paging.page_align( input_data->m_size + page_offset );
        if ( total_size == 0 ) {
            total_size = mm::paging::page_4kb_size;
        }

        auto mapped_va = reinterpret_cast< std::uintptr_t >(
            nt::mm_map_io_space( aligned_phys , total_size )
            );

        if ( !mapped_va ) {
            return nt_status_t::unsuccessful;
        }

        input_data->m_address2 = mapped_va + page_offset;
        input_data->m_size = total_size;

        return nt_status_t::success;
    }
}