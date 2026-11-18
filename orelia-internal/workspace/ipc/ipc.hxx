#pragma once

namespace pipe {
    const std::uint32_t in_success_state = 1;
    const std::uint32_t in_progressive_state = 2;
    const std::uint32_t in_failure_state = 3;
    const std::uint32_t magic_code = 0xDEADBEEF;

    enum class e_command_type : std::uint32_t {
        ping_server,
        debug_print,
        message_box,
        move_mouse,
        reset_mouse
    };

    struct s_command_data {
        std::uint32_t pid{};
        std::uintptr_t address{};
        std::uintptr_t address2{};
        std::size_t size{};
        void* buffer{};
        char format[ 256 ]{};
        std::uint32_t m_x{};
        std::uint32_t m_y{};
    };

    class c_command_data {
    public:
        c_command_data( ) = default;
        c_command_data(
            e_command_type type,
            s_command_data data,
            std::uint32_t magic_code,
            bool priority = false )
            : m_type( type ), m_data( data ), m_magic_code( magic_code ), m_completed( false ) {
        }

        bool is_completed( ) const { return m_completed; }
        void set_completed( bool state ) { m_completed = state; }

        std::uint32_t get_magic( ) const { return m_magic_code; }
        std::uint32_t get_status( ) const { return m_status_code; }
        void set_status( std::uint32_t status ) { m_status_code = status; }

        e_command_type get_type( ) const { return m_type; }
        const s_command_data& get_data( ) const { return m_data; }

    private:
        e_command_type m_type;
        s_command_data m_data;
        bool m_completed;
        std::uint32_t m_status_code;
        std::uint32_t m_magic_code;
        std::uint64_t m_timestamp;
    };

        // ... existing code ...

        class c_pipe {
        public:
            c_pipe( ) = default;
            ~c_pipe( ) {
                cleanup( );
            }

            bool send_cmd( c_command_data& command ) const {
                if ( !m_registry_key ) return false;

                // Convert command to binary data
                DWORD data_size = sizeof( command );
                BYTE* data = reinterpret_cast< BYTE* >( &command );

                // Write command to registry
                LONG result = RegSetValueExA(
                    m_registry_key,
                    "Command",
                    0,
                    REG_BINARY,
                    data,
                    data_size
                );

                if ( result != ERROR_SUCCESS ) {
                    return false;
                }

                // Release mutex to notify clients
                ReleaseMutex( m_mutex );
                return true;
            }

            c_command_data get_cmd( ) const {
                c_command_data data;
                if ( !m_registry_key ) return data;

                // Wait for mutex signal
                if ( WaitForSingleObject( m_mutex, INFINITE ) != WAIT_OBJECT_0 ) {
                    return data;
                }

                // Read command from registry
                DWORD data_size = sizeof( data );
                BYTE* buffer = reinterpret_cast< BYTE* >( &data );
                DWORD type = REG_BINARY;

                LONG result = RegQueryValueExA(
                    m_registry_key,
                    "Command",
                    nullptr,
                    &type,
                    buffer,
                    &data_size
                );

                ReleaseMutex( m_mutex );

                if ( result != ERROR_SUCCESS ) {
                    return c_command_data( );
                }

                return data;
            }

            bool create_buffer( const char* name ) {
                SECURITY_DESCRIPTOR sd;
                InitializeSecurityDescriptor( &sd, SECURITY_DESCRIPTOR_REVISION );
                SetSecurityDescriptorDacl( &sd, TRUE, NULL, FALSE );

                SECURITY_ATTRIBUTES sa;
                sa.nLength = sizeof( SECURITY_ATTRIBUTES );
                sa.lpSecurityDescriptor = &sd;
                sa.bInheritHandle = FALSE;

                char mutex_name[ 256 ];
                sprintf_s( mutex_name, "%s_mutex", name );
                m_mutex = CreateMutexA( &sa, FALSE, mutex_name );
                if ( !m_mutex ) {
                    return false;
                }

                char key_path[ 256 ];
                sprintf_s( key_path, "SOFTWARE\\Orelia\\%s", name );
                LONG result = RegCreateKeyExA(
                    HKEY_CURRENT_USER,
                    key_path,
                    0,
                    nullptr,
                    REG_OPTION_NON_VOLATILE,
                    KEY_ALL_ACCESS,
                    &sa,
                    &m_registry_key,
                    nullptr
                );

                if ( result != ERROR_SUCCESS ) {
                    CloseHandle( m_mutex );
                    m_mutex = nullptr;
                    return false;
                }

                return true;
            }

            bool create( ) {
                return create_buffer( "OreliaIPC" );
            }

            bool is_connected( ) const {
                return m_registry_key != nullptr && m_mutex != nullptr;
            }

            bool wait_for_connection( ) const {
                return is_connected( );
            }

        private:
            HKEY m_registry_key = nullptr;
            HANDLE m_mutex = nullptr;

            void cleanup( ) {
                if ( m_registry_key ) {
                    RegCloseKey( m_registry_key );
                    m_registry_key = nullptr;
                }
                if ( m_mutex ) {
                    CloseHandle( m_mutex );
                    m_mutex = nullptr;
                }
            }
        };
    }