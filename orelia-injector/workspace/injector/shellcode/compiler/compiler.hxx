namespace compiler {
    using namespace asmjit;
    using namespace asmjit::x86;

    class c_compiler {
    public:
        void setup( ) {
            m_code = std::make_unique<CodeHolder>( );
            m_code->init( m_runtime.environment( ) );

            m_assembler = std::make_unique<Assembler>( m_code.get( ) );
            m_data_label = m_assembler->newLabel( );
        }

        void create_stack( int size ) {
            m_assembler->sub( rsp, Imm( size ) );
        }

        void restore_stack( int size ) {
            m_assembler->add( rsp, Imm( size ) );
        }

        void setup_registers( ) {
            m_assembler->push( rax );
            m_assembler->push( rcx );
            m_assembler->push( rdx );
            m_assembler->push( r8 );
            m_assembler->push( r9 );
            m_assembler->push( r11 );
            m_assembler->push( r10 );
            m_assembler->push( rbx );
            m_assembler->push( rsi );
            m_assembler->push( rdi );
            m_assembler->push( rbp );
        }

        void restore_registers( ) {
            m_assembler->pop( rbp );
            m_assembler->pop( rdi );
            m_assembler->pop( rsi );
            m_assembler->pop( rbx );
            m_assembler->pop( r10 );
            m_assembler->pop( r11 );
            m_assembler->pop( r9 );
            m_assembler->pop( r8 );
            m_assembler->pop( rdx );
            m_assembler->pop( rcx );
            m_assembler->pop( rax );
        }

        void store_data( ) {
            m_assembler->mov( rax, qword_ptr( m_data_label ) );
            m_assembler->mov( qword_ptr( rsp, 0x20 ), rax );
        }

        void create_frame( ) {
            /* 0x20 keeps rsp 16-byte aligned before `call` and provides the
             * 32-byte shadow space the Windows x64 ABI requires. A 0x1C
             * frame lands the callee at rsp%16==12 and any movaps spill in
             * ntdll raises an access violation. */
            m_assembler->and_( rsp, Imm( -16 ) );
            m_assembler->sub( rsp, Imm( 0x20 ) );
        }

        void restore_frame( ) {
            m_assembler->add( rsp, Imm( 0x20 ) );
        }

        void check_status( ) {
            m_assembler->mov( rax, qword_ptr( rsp, 0x20 ) );
            m_assembler->cmp( dword_ptr( rax, offsetof( shellcode::inject_data_t, m_status ) ), Imm( 0 ) );

            m_execution_skip_label = m_assembler->newLabel( );
            m_assembler->jne( m_execution_skip_label );
        }

        void bind_execution_skip( ) {
            m_assembler->bind( m_execution_skip_label );
        }

        /* Only the OBS present shim may start the payload. [rsp + 0x58] is the
         * return address above the 11 saved registers; a slot the scan guessed
         * wrong is still called from somewhere else, so the shellcode jumps
         * straight to the original instead of running DllMain from a random
         * caller. rax/r10 are volatile here and restored by restore_registers. */
        void guard_caller( ) {
            m_assembler->mov( rax, qword_ptr( rsp, 0x20 ) );
            m_assembler->mov( r10, qword_ptr( rsp, 0x58 ) );
            m_assembler->mov( qword_ptr( rax, offsetof( shellcode::inject_data_t, m_last_caller ) ), r10 );
            m_assembler->mov( rax, qword_ptr( rax, offsetof( shellcode::inject_data_t, m_hook_base ) ) );
            m_assembler->sub( r10, rax );
            m_assembler->mov( rax, qword_ptr( rsp, 0x20 ) );
            m_assembler->mov( rax, qword_ptr( rax, offsetof( shellcode::inject_data_t, m_hook_size ) ) );
            m_assembler->cmp( r10, rax );
            m_assembler->jae( m_execution_skip_label );
        }

        void set_rcx( std::uint64_t a1 ) {
            m_assembler->mov( rcx, Imm( a1 ) );
        }

        void set_rdx( std::uint32_t a2 ) {
            m_assembler->mov( rdx, Imm( a2 ) );
        }

        void set_r8( std::uint64_t a3 ) {
            m_assembler->mov( r8, Imm( a3 ) );
        }

        void set_rax( std::uint64_t addr ) {
            m_assembler->mov( rax, Imm( addr ) );
        }

        void call_rax( ) {
            m_assembler->call( rax );
        }

        void jmp_rax( ) {
            m_assembler->jmp( rax );
        }

        void set_status( int status ) {
            m_assembler->mov( rax, qword_ptr( rsp, 0x20 ) );
            m_assembler->mov( dword_ptr( rax, offsetof( shellcode::inject_data_t, m_status ) ), Imm( status ) );
        }

        void store_return( ) {
            m_assembler->mov( rcx, qword_ptr( rsp, 0x20 ) );
            m_assembler->mov( dword_ptr( rcx, offsetof( shellcode::inject_data_t, m_return ) ), eax );
        }

        void ret( ) {
            m_assembler->ret( );
        }

        void int3( ) {
            m_assembler->int3( );
        }

        void add_random_nops( int min_count = 1, int max_count = 5 ) {
            int nop_count = min_count + ( std::rand( ) % ( max_count - min_count + 1 ) );
            for ( int i = 0; i < nop_count; i++ ) {
                m_assembler->nop( );
            }
        }

        void set_hook_range( std::uint64_t base, std::uint64_t size ) {
            m_hook_base = base;
            m_hook_size = size;
        }

        bool set_data_ref( std::uint64_t* data_va ) {
            shellcode::inject_data_t inject_data{};
            inject_data.m_return = 0;
            inject_data.m_status = 0;
            inject_data.m_hook_base = m_hook_base;
            inject_data.m_hook_size = m_hook_size;

            *data_va = g_driver->allocate_virtual( sizeof( inject_data ) );
            if ( !*data_va ) {
                logging::print( encrypt( "Failed to allocate data buffer" ) );
                return false;
            }

            m_assembler->bind( m_data_label );
            m_assembler->dq( *data_va );

            return g_driver->write_memory( *data_va, &inject_data, sizeof( inject_data ) );
        }

        bool generate( std::uint64_t* shellcode_va ) {
            auto err = m_assembler->finalize( );
            if ( err ) {
                logging::print( encrypt( "AsmJit finalize error: %d" ), err );
                return false;
            }

            auto& buffer = m_code->sectionById( 0 )->buffer( );
            auto size = buffer.size( );
            if ( size == 0 ) {
                logging::print( encrypt( "AsmJit generated empty buffer" ) );
                return false;
            }

            *shellcode_va = g_driver->allocate_virtual( size );
            if ( !*shellcode_va ) {
                logging::print( encrypt( "Failed to allocate shellcode buffer" ) );
                return false;
            }

            return g_driver->write_memory( *shellcode_va, buffer.data( ), size );
        }

    private:
        asmjit::JitRuntime m_runtime;
        std::unique_ptr<CodeHolder> m_code;
        std::unique_ptr<Assembler> m_assembler;
        Label m_data_label;
        Label m_execution_skip_label;
        std::uint64_t m_hook_base = 0;
        std::uint64_t m_hook_size = 0;
    };
}
