#pragma once
#include <cstring>
#include <cstdlib>
#include <cwchar>

namespace shellcode {
	namespace detail {
		struct section_t {
			std::wstring name;
			std::uintptr_t base;
			std::uint32_t size;
			bool executable;
			bool writable;
		};

		struct module_t {
			std::uintptr_t base;
			std::uint32_t size;
			std::wstring name;
		};

		struct candidate_t {
			std::uintptr_t slot;
			std::uintptr_t value;
			int rank;
			bool referenced;
			std::wstring module;
		};

		/* Module names come from the PEB with the on-disk casing (dxgi.dll is
		 * lowercase, D3D10_1.dll is not), so match without it. */
		inline bool name_has( const std::wstring& name, const wchar_t* needle ) {
			const size_t length = std::wcslen( needle );
			if ( !length || name.size( ) < length )
				return false;
			for ( size_t i = 0; i + length <= name.size( ); ++i )
				if ( _wcsnicmp( name.c_str( ) + i, needle, length ) == 0 )
					return true;
			return false;
		}

		/* Graphics-hook is parsed out of the target's own memory: only the
		 * loaded image reflects the OBS build actually hooked into the game. */
		inline bool read_image_sections( std::uintptr_t module_base, std::vector< section_t >& out ) {
			IMAGE_DOS_HEADER dos{};
			if ( !g_driver->read_memory( module_base, &dos, sizeof( dos ) ) || dos.e_magic != IMAGE_DOS_SIGNATURE )
				return false;

			IMAGE_NT_HEADERS64 nt{};
			if ( !g_driver->read_memory( module_base + dos.e_lfanew, &nt, sizeof( nt ) ) )
				return false;
			if ( nt.Signature != IMAGE_NT_SIGNATURE )
				return false;

			const std::uintptr_t table = module_base + dos.e_lfanew + sizeof( DWORD ) +
				sizeof( IMAGE_FILE_HEADER ) + nt.FileHeader.SizeOfOptionalHeader;

			for ( unsigned i = 0; i < nt.FileHeader.NumberOfSections; i++ ) {
				IMAGE_SECTION_HEADER header{};
				if ( !g_driver->read_memory( table + i * sizeof( IMAGE_SECTION_HEADER ), &header, sizeof( header ) ) )
					return false;

				section_t section{};
				char name[ 9 ]{};
				std::memcpy( name, header.Name, 8 );
				for ( const char* c = name; *c; c++ )
					section.name.push_back( (wchar_t)(unsigned char)*c );
				section.base = module_base + header.VirtualAddress;
				section.size = header.Misc.VirtualSize ? header.Misc.VirtualSize : header.SizeOfRawData;
				section.executable = ( header.Characteristics & IMAGE_SCN_MEM_EXECUTE ) != 0;
				section.writable = ( header.Characteristics & IMAGE_SCN_MEM_WRITE ) != 0;
				out.push_back( section );
			}

			return !out.empty( );
		}

		inline std::vector< module_t > process_modules( ) {
			std::vector< module_t > modules;
			for ( const auto& [base, name] : g_driver->get_process_modules( ) ) {
				IMAGE_DOS_HEADER dos{};
				if ( !g_driver->read_memory( base, &dos, sizeof( dos ) ) || dos.e_magic != IMAGE_DOS_SIGNATURE )
					continue;

				IMAGE_NT_HEADERS64 nt{};
				if ( !g_driver->read_memory( base + dos.e_lfanew, &nt, sizeof( nt ) ) ||
					nt.Signature != IMAGE_NT_SIGNATURE )
					continue;

				modules.push_back( { base, nt.OptionalHeader.SizeOfImage, name } );
			}
			return modules;
		}

		inline const module_t* owner_of( const std::vector< module_t >& modules, std::uintptr_t value ) {
			for ( const auto& module : modules )
				if ( value >= module.base && value < module.base + module.size )
					return &module;
			return nullptr;
		}

		/* Lower is tried first. dxgi/d3d11 lead because a Unity title on
		 * Windows presents through them; opengl32 trails because a
		 * graphics-hook build also carries a wglSwapBuffers pointer that is
		 * never called inside a D3D game. */
		inline int api_rank( const std::wstring& name ) {
			if ( name_has( name, L"dxgi" ) ) return 1;
			if ( name_has( name, L"d3d11" ) ) return 2;
			if ( name_has( name, L"d3d12" ) ) return 3;
			if ( name_has( name, L"d3d10" ) ) return 3;
			if ( name_has( name, L"d3d9" ) ) return 4;
			if ( name_has( name, L"opengl32" ) ) return 5;
			return 6;
		}

		/* A pointer slot only matters if the hook actually loads it through
		 * code; a copy sitting in .data is inert.  We recognise several
		 * common RIP-relative load patterns:
		 *   48 8B [modrm=xx000101] disp32  ->  mov rax/rcx/rdx/..., [rip+disp] (REX.W)
		 *   48 8D [modrm=xx000101] disp32  ->  lea reg, [rip+disp]             (REX.W)
		 *   FF 25 disp32                   ->  jmp  [rip+disp]
		 *   FF 15 disp32                   ->  call [rip+disp]
		 * The wider set catches OBS builds that use LEA+CALL or indirect
		 * JMP/CALL through the saved pointer instead of a plain MOV.
		 * Targets land in one sorted list so a data slot is classified in
		 * O(log n) instead of a full text re-scan per candidate. */
		inline void collect_slot_xrefs( const std::vector< std::uint8_t >& text, std::uintptr_t text_base,
			std::vector< std::uintptr_t >& out ) {
			for ( size_t i = 0; i < text.size( ); i++ ) {
				/* Pattern 1: REX.W MOV reg, [rip+disp32]  (48/4C 8B modrm)
				 * Pattern 2: REX.W LEA reg, [rip+disp32]  (48/4C 8D modrm)
				 * With modrm.rm == 101 the displacement is RIP-relative only
				 * while REX.B is clear, so the legal prefixes are 0x48
				 * (rax..rdi) and 0x4C (r8..r15); 0x49/0x4D would encode
				 * [r13+disp] and must not match. */
				if ( i + 7 <= text.size( ) && ( text[ i ] == 0x48 || text[ i ] == 0x4C ) &&
					( text[ i + 1 ] == 0x8B || text[ i + 1 ] == 0x8D ) &&
					( text[ i + 2 ] & 0xC7 ) == 0x05 ) {
					std::int32_t disp = 0;
					std::memcpy( &disp, text.data( ) + i + 3, sizeof( disp ) );
					out.push_back( text_base + i + 7 + (std::intptr_t)disp );
				}

				/* Pattern 3: FF 15 disp32  ->  call [rip+disp]
				 * Pattern 4: FF 25 disp32  ->  jmp [rip+disp] */
				if ( i + 6 <= text.size( ) && text[ i ] == 0xFF &&
					( text[ i + 1 ] == 0x15 || text[ i + 1 ] == 0x25 ) ) {
					std::int32_t disp = 0;
					std::memcpy( &disp, text.data( ) + i + 2, sizeof( disp ) );
					out.push_back( text_base + i + 6 + (std::intptr_t)disp );
				}
			}

			std::sort( out.begin( ), out.end( ) );
			out.erase( std::unique( out.begin( ), out.end( ) ), out.end( ) );
		}

		inline std::uint32_t image_size_of( std::uintptr_t module_base ) {
			IMAGE_DOS_HEADER dos{};
			if ( !g_driver->read_memory( module_base, &dos, sizeof( dos ) ) || dos.e_magic != IMAGE_DOS_SIGNATURE )
				return 0;

			IMAGE_NT_HEADERS64 nt{};
			if ( !g_driver->read_memory( module_base + dos.e_lfanew, &nt, sizeof( nt ) ) ||
				nt.Signature != IMAGE_NT_SIGNATURE )
				return 0;

			return nt.OptionalHeader.SizeOfImage;
		}

		/* The real Present pointer is a slot in a writable section of the hook
		 * module. OBS relinks graphics-hook every release, so the slot is found
		 * by shape and ordered by evidence instead of by a per-build RVA.
		 * Two shapes exist:
		 *   - a build without Detours keeps the original straight into
		 *     d3d11/dxgi/opengl32, so the value lands inside a module,
		 *   - a build with Detours keeps it in a private trampoline, so the
		 *     value lands in no module at all and only the code reference
		 *     marks it.
		 * The second shape is why a scan that demanded a module owner patched
		 * a live opengl32 slot and reported "never called": the real slot was
		 * invisible to it. Nothing here proves a slot is live, so the list is
		 * ordered best guess first and run() probes every entry. */
		inline void collect_present_slots( std::uintptr_t hook_base, const std::vector< module_t >& modules,
			bool verbose, std::vector< std::uintptr_t >& out, size_t max_slots ) {
			std::vector< section_t > sections;
			if ( !read_image_sections( hook_base, sections ) ) {
				logging::print( encrypt( "Failed to parse graphics-hook64 headers at 0x%llX." ), hook_base );
				return;
			}

			const section_t* text = nullptr;
			for ( const auto& section : sections )
				if ( section.name == L".text" ) text = &section;

			std::vector< std::uintptr_t > xrefs;
			if ( text ) {
				const std::uint32_t code_size = text->size < 0x200000 ? text->size : 0x200000;
				std::vector< std::uint8_t > code( code_size );
				if ( g_driver->read_memory( text->base, code.data( ), code.size( ) ) ) {
					code.resize( code_size );
					collect_slot_xrefs( code, text->base, xrefs );
				}
			}

			std::vector< candidate_t > candidates;
			int self_refs = 0;

			/* 4 MiB of hook data is far past any layout seen so far, and the
			 * bound keeps a hostile or corrupt section size from turning the
			 * scan into a multi-second read per attempt. */
			size_t budget = 0x400000;
			for ( const auto& section : sections ) {
				if ( !section.writable || section.executable || !section.size || !budget )
					continue;

				const std::uint32_t size = section.size < 0x100000 ? section.size : 0x100000;
				std::vector< std::uint8_t > blob( size );
				if ( !g_driver->read_memory( section.base, blob.data( ), blob.size( ) ) )
					continue;
				budget -= size;

				for ( size_t offset = 0; offset + sizeof( std::uint64_t ) <= blob.size( ); offset += sizeof( std::uint64_t ) ) {
					std::uint64_t value = 0;
					std::memcpy( &value, blob.data( ) + offset, sizeof( value ) );
					if ( value < 0x10000 || value > 0x00007FFFFFFFFFFF )
						continue;

					const module_t* owner = owner_of( modules, (std::uintptr_t)value );

					if ( owner && _wcsicmp( owner->name.c_str( ), L"graphics-hook64.dll" ) == 0 ) {
						/* Its own code pointers are hook shims, never the
						 * original Present; log a few so an unfamiliar
						 * layout can be identified from the output. */
						if ( verbose && self_refs < 4 ) {
							logging::print( encrypt( "  self-pointer slot 0x%llX -> +0x%llX (skipped)" ),
								section.base + offset, (unsigned long long)( value - hook_base ) );
							++self_refs;
						}
						continue;
					}

					candidate_t candidate{ section.base + offset, (std::uintptr_t)value, 0, false, L"private" };
					candidate.referenced =
						std::binary_search( xrefs.begin( ), xrefs.end( ), candidate.slot );
					if ( owner ) {
						candidate.module = owner->name;
						candidate.rank = api_rank( owner->name );
					}

					/* Keep a slot only with evidence: a code reference means
					 * the hook loads it, and a dxgi/d3d11 value means it is
					 * the original Present even when the call itself was
					 * missed (indirect jump through another table, code past
					 * the scanned range). Everything else is inert data. */
					const bool graphics_api = owner &&
						( name_has( owner->name, L"dxgi" ) || name_has( owner->name, L"d3d11" ) );
					if ( !candidate.referenced && !graphics_api )
						continue;

					if ( verbose )
						logging::print( encrypt( "  candidate 0x%llX -> 0x%llX (%ls, xref=%s)" ),
							candidate.slot, candidate.value, candidate.module.c_str( ),
							candidate.referenced ? "yes" : "no" );

					candidates.push_back( candidate );
				}
			}

			if ( candidates.empty( ) ) {
				if ( verbose )
					logging::print( encrypt( "No Present pointer in hook data yet." ) );
				return;
			}

			/* Referenced slots first, then the API that the title presents
			 * through; private trampolines are rank 0 so they still lead a
			 * Detours build. */
			std::stable_sort( candidates.begin( ), candidates.end( ),
				[]( const candidate_t& a, const candidate_t& b ) {
					if ( a.referenced != b.referenced ) return a.referenced;
					if ( a.rank != b.rank ) return a.rank < b.rank;
					return a.slot < b.slot;
				} );

			for ( const auto& candidate : candidates ) {
				if ( out.size( ) >= max_slots )
					break;
				if ( std::find( out.begin( ), out.end( ), candidate.slot ) != out.end( ) )
					continue;
				out.push_back( candidate.slot );
			}
		}

		/* Module name of whatever backs a slot, for the attempt log. */
		inline std::wstring slot_owner( const std::vector< module_t >& modules, std::uint64_t value ) {
			const module_t* owner = owner_of( modules, (std::uintptr_t)value );
			return owner ? owner->name : L"private";
		}
	}

	class c_shellcode {
	public:
		c_shellcode( std::uint64_t dll_main ) :
			m_entry_point( dll_main ), m_reflective_mode( false ) {
		}

		c_shellcode( std::uint64_t reflective_loader, reflective::reflective_data_t reflective_data ) :
			m_entry_point( reflective_loader ), m_reflective_data( reflective_data ), m_reflective_mode( true ) {
		}

		bool setup( bool allow_legacy = true ) {
			auto graphicshook64 = g_driver->get_process_module( encrypt( L"graphics-hook64.dll" ) );
			if ( !graphicshook64 ) {
				logging::print( encrypt( "graphics-hook64.dll is not loaded in the target process." ) );
				logging::print( encrypt( "Start OBS, add a Game Capture source for the title, press Start Capture, then run this again." ) );
				return false;
			}

			logging::print( encrypt( "graphics-hook64.dll at 0x%llX, locating Present slot" ), graphicshook64 );

			/* One enumeration for the whole wait: the module list does not
			 * change once graphics-hook64 is loaded, and every call walks the
			 * PEB. */
			const auto modules = detail::process_modules( );
			m_modules = modules;

			/* The historical RVA is the fast path. Detours keeps the original
			 * outside every module, so the value is not range-checked. It is
			 * also dumped from one graphics-hook64 build: a different OBS
			 * release keeps unrelated data at that offset that still reads as
			 * a pointer, the patched slot is never loaded by the render
			 * thread, and run() ends on a timeout. The slot is only a guess,
			 * so it is tried first and every other candidate follows. */
			const std::uint64_t legacy = g_driver->read( graphicshook64 + 0x42DC8 );
			if ( allow_legacy && legacy > 0x10000 && legacy < 0x00007FFFFFFFFFFF ) {
				logging::print( encrypt( "Present slot at legacy RVA 0x42DC8 -> 0x%llX" ), legacy );
				m_slots.push_back( graphicshook64 + 0x42DC8 );
				m_legacy_slot = true;
			}

			/* Escape hatch for a hook layout the scan does not recognise:
			 * hex RVA of the RealPresent slot, relative to graphics-hook64. */
			wchar_t override_rva[ 32 ]{};
			if ( GetEnvironmentVariableW( L"ORELIA_PRESENT_RVA", override_rva, 32 ) > 0 ) {
				wchar_t* end = nullptr;
				const unsigned long long rva = std::wcstoull( override_rva, &end, 16 );
				if ( rva > 0x1000 && rva < 0x10000000 ) {
					const std::uint64_t slot = graphicshook64 + rva;
					const std::uint64_t value = g_driver->read( slot );
					if ( value > 0x10000 && value < 0x00007FFFFFFFFFFF ) {
						logging::print( encrypt( "Present slot forced by ORELIA_PRESENT_RVA: 0x%llX -> 0x%llX" ), slot, value );
						m_slots.insert( m_slots.begin( ), slot );
					} else {
						logging::print( encrypt( "ORELIA_PRESENT_RVA 0x%llX reads zero; ignored." ), rva );
					}
				}
			}

			const int max_attempts = 120;

			/* OBS installs its hook asynchronously; the pointer stays null
			 * until the capture thread binds, so wait instead of failing. The
			 * scan always runs, even when the legacy RVA produced a slot: that
			 * offset only matches one build and its hit is just the first
			 * guess run() probes. */
			std::vector< std::uintptr_t > scanned;
			for ( int attempt = 0; attempt < max_attempts; attempt++ ) {
				detail::collect_present_slots( graphicshook64, modules, attempt == 0 || attempt == max_attempts - 1,
					scanned, k_max_slots );
				if ( !scanned.empty( ) )
					break;
				if ( attempt && attempt % 20 == 19 )
					logging::print( encrypt( "Still waiting for the D3D Present slot (%d s) - keep the Game Capture preview running." ), ( attempt + 1 ) / 2 );
				Sleep( 500 );
			}

			for ( const auto slot : scanned ) {
				if ( m_slots.size( ) >= k_max_slots )
					break;
				if ( std::find( m_slots.begin( ), m_slots.end( ), slot ) != m_slots.end( ) )
					continue;
				m_slots.push_back( slot );
			}

			if ( m_slots.empty( ) ) {
				logging::print( encrypt( "No Present slot after %d s; the hook is loaded but has not attached to the title." ),
					max_attempts / 2 );
				logging::print( encrypt( "Run OBS as administrator, add Game Capture -> ROB RUN to the active scene," ) );
				logging::print( encrypt( "confirm the preview shows the game, then inject again." ) );
				return false;
			}

			m_hook_base = graphicshook64;
			m_hook_size = detail::image_size_of( graphicshook64 );
			if ( !m_hook_size ) {
				logging::print( encrypt( "graphics-hook64 image size unreadable." ) );
				return false;
			}

			logging::print( encrypt( "%zu candidate slot(s) queued; each is patched and watched for one frame budget." ),
				m_slots.size( ) );

			if ( m_reflective_mode ) {
				this->m_reflective_data_va = g_driver->allocate_virtual( sizeof( m_reflective_data ) );
				if ( !m_reflective_data_va ) {
					logging::print( encrypt( "Failed to allocate reflective data" ) );
					return false;
				}

				if ( !g_driver->write_memory( m_reflective_data_va, &m_reflective_data, sizeof( m_reflective_data ) ) ) {
					logging::print( encrypt( "Failed to create reflective context" ) );
					return false;
				}
			}

			return true;
		}

		bool update( ) {
			/* A failed probe rebuilds the code for the next slot; the previous
			 * buffer must go first or every retry leaks a page pair. */
			release_code( );

			auto compiler = std::make_unique<compiler::c_compiler>( );
			compiler->setup( );
			compiler->setup_registers( );
			compiler->add_random_nops( );

			compiler->store_data( );
			compiler->guard_caller( );
			compiler->check_status( );
			compiler->add_random_nops( );

			compiler->set_status( 1 );

			if ( m_reflective_mode ) {
				compiler->set_rcx( m_reflective_data_va );
			}
			else {
				compiler->set_rcx( g_driver->m_base_address );
				compiler->set_rdx( DLL_PROCESS_ATTACH );
				/* r8 carries the mapped image base so the payload can find
				 * its own headers without scanning backwards. */
				compiler->set_r8( m_image_base );
			}

			compiler->add_random_nops( );

			compiler->set_status( 2 );
			compiler->create_frame( );
			compiler->set_rax( m_entry_point );
			compiler->call_rax( );
			compiler->restore_frame( );
			compiler->add_random_nops( );

			compiler->store_return( );
			compiler->set_status( 3 );
			compiler->add_random_nops( );

			compiler->bind_execution_skip( );
			compiler->restore_registers( );
			compiler->add_random_nops( );

			compiler->set_rax( m_original_fn );
			compiler->jmp_rax( );

			compiler->set_hook_range( m_hook_base, m_hook_size );

			if ( !compiler->set_data_ref( &m_data_va ) ) {
				logging::print( encrypt( "Failed to generate xrefs." ) );
				return false;
			}

			if ( !compiler->generate( &m_shellcode_va ) ) {
				logging::print( encrypt( "Failed to generate shellcode." ) );
				return false;
			}

			logging::print( encrypt( "Shellcode initialization complete:" ) );
			logging::print( encrypt( "  - Inject address: 0x%llX" ), m_inject_address );
			logging::print( encrypt( "  - Original target: 0x%llX" ), m_original_fn );

			if ( m_reflective_mode ) {
				logging::print( encrypt( "  - Reflective data: 0x%llX" ), m_reflective_data_va );
			}

			logging::print( encrypt( "  - Entrypoint: 0x%llX" ), m_entry_point );
			logging::print( encrypt( "Successfully initializated shellcode\n" ) );
			return true;
		}

		/* Every candidate gets its own live test: patch, poll for one Present
		 * interval, and if the slot never ran, put the original back before
		 * the next one. A wrong guess used to end the whole run because the
		 * first slot came from a per-build RVA or because the scan's best
		 * module-ranked hit was an API the title does not call. */
		bool run( ) {
			if ( m_slots.empty( ) ) {
				logging::print( encrypt( "No slot to patch." ) );
				return false;
			}

			logging::print( encrypt( "Waiting for module initialization" ) );

			size_t attempted = 0;
			for ( size_t index = 0; index < m_slots.size( ); index++ ) {
				m_inject_address = m_slots[ index ];
				m_timed_out = false;
				m_remote_data = {};

				const std::uint64_t original = g_driver->read( m_inject_address );
				if ( original < 0x10000 || original > 0x00007FFFFFFFFFFF ||
					original == m_shellcode_va ) {
					logging::print( encrypt( "Slot %zu/%zu at 0x%llX holds no callable pointer (0x%llX); skipped." ),
						index + 1, m_slots.size( ), m_inject_address, original );
					continue;
				}

				m_original_fn = original;

				if ( !update( ) ) {
					logging::print( encrypt( "Failed to compile shellcode for slot 0x%llX." ), m_inject_address );
					return false;
				}

				logging::print( encrypt( "Probing slot %zu/%zu at 0x%llX -> 0x%llX (%ls)." ),
					index + 1, m_slots.size( ), m_inject_address, m_original_fn,
					detail::slot_owner( m_modules, m_original_fn ).c_str( ) );

				const bool written = g_driver->write( m_inject_address, m_shellcode_va );
				std::uint64_t installed = 0;
				if ( !g_driver->read_memory( m_inject_address, &installed, sizeof( installed ) ) ) {
					logging::print( encrypt( "Could not verify slot 0x%llX after writing (write=%d)." ),
						m_inject_address, (int)written );
					restore_slot( );
					return false;
				}
				if ( installed != m_shellcode_va ) {
					logging::print( encrypt( "Slot 0x%llX rejected the patch (write=%d, readback=0x%llX); skipped." ),
						m_inject_address, (int)written, installed );
					m_inject_address = 0;
					continue;
				}
				++attempted;

				/* 1.5 s is roughly 90 presents at 60 Hz; a slot that is live
				 * is hit dozens of times inside it. */
				const auto deadline = std::chrono::steady_clock::now( ) + std::chrono::milliseconds( 1500 );
				bool fired = false;

				while ( std::chrono::steady_clock::now( ) < deadline ) {
					if ( !g_driver->get_process_id( target_process ) ) {
						debug_exception( );
						restore_slot( );
						return false;
					}

					if ( m_reflective_mode ) {
						g_driver->read_memory( m_reflective_data_va, &m_reflective_data, sizeof( m_reflective_data ) );
					}

					shellcode::inject_data_t sample{};
					if ( g_driver->read_memory( m_data_va, &sample, sizeof( sample ) ) )
						m_remote_data = sample;
					if ( m_remote_data.m_status == 3 ) {
						fired = true;
						break;
					}

					std::this_thread::sleep_for( std::chrono::milliseconds( 25 ) );
				}

				if ( fired ) {
					logging::print( encrypt( "Module initialization complete:" ) );
					logging::print( encrypt( "  - Shellcode Status: %i" ), m_remote_data.m_status );

					if ( m_reflective_mode ) {
						logging::print( encrypt( "  - Reflective Return: %i" ), m_remote_data.m_return );
						logging::print( encrypt( "  - DllMain Return: %i" ), m_reflective_data.m_dll_return );
					}
					else {
						logging::print( encrypt( "  - Shellcode Return: %i" ), m_remote_data.m_return );
					}

					logging::print( encrypt( "Successfully initialized module\n" ) );
					return true;
				}

				m_timed_out = true;
				logging::print( encrypt( "Slot 0x%llX did not complete in 1.5 s (last status=%d)." ),
					m_inject_address, m_remote_data.m_status );
				if ( m_remote_data.m_status == 0 && m_remote_data.m_last_caller )
					logging::print( encrypt( "Callback was reached from 0x%llX (%ls), outside the OBS caller range." ),
						m_remote_data.m_last_caller,
						detail::slot_owner( m_modules, m_remote_data.m_last_caller ).c_str( ) );
				restore_slot( );
				if ( initialization_in_progress( ) )
					return false;
				m_inject_address = 0;
			}

			logging::print( encrypt( "No startup was observed across %zu verified slot patch(es)." ), attempted );
			logging::print( encrypt( "Keep the game window open and focused: Unity stops presenting while minimized," ) );
			logging::print( encrypt( "and an idle Game Capture means Present never fires. Nothing was left behind." ) );
			return false;
		}

		void cleanup( ) const {
			restore_slot( );
			if ( initialization_in_progress( ) ) return;

			if ( m_data_va ) g_driver->free_virtual( m_data_va );
			if ( m_shellcode_va ) g_driver->free_virtual( m_shellcode_va );
			if ( m_reflective_data_va ) g_driver->free_virtual( m_reflective_data_va );
		}

		bool initialization_in_progress( ) const {
			return m_remote_data.m_status == 1 || m_remote_data.m_status == 2;
		}

		void set_image_base( std::uint64_t image_base ) {
			m_image_base = image_base;
		}

		/* True when the slot came from the hardcoded RVA instead of the
		 * scan: the only case worth reporting as a layout mismatch. */
		bool used_legacy_slot( ) const {
			return m_legacy_slot;
		}

		bool timed_out( ) const {
			return m_timed_out;
		}

	private:
		static constexpr size_t k_max_slots = 24;

		std::uint64_t m_data_va = 0;
		std::uint64_t m_shellcode_va = 0;
		std::uint64_t m_inject_address = 0;
		std::uint64_t m_original_fn = 0;
		std::uint64_t m_entry_point = 0;
		std::uint64_t m_image_base = 0;
		std::uint64_t m_reflective_data_va = 0;
		std::uint64_t m_hook_base = 0;
		std::uint64_t m_hook_size = 0;
		bool m_reflective_mode = false;
		bool m_legacy_slot = false;
		bool m_timed_out = false;
		std::vector< std::uintptr_t > m_slots;
		std::vector< detail::module_t > m_modules;
		shellcode::inject_data_t m_remote_data{};
		reflective::reflective_data_t m_reflective_data{};

		void restore_slot( ) const {
			if ( m_inject_address && m_original_fn && m_shellcode_va &&
				g_driver->read( m_inject_address ) == m_shellcode_va )
				g_driver->write( m_inject_address, m_original_fn );
		}

		void release_code( ) {
			if ( m_data_va ) {
				g_driver->free_virtual( m_data_va );
				m_data_va = 0;
			}

			if ( m_shellcode_va ) {
				g_driver->free_virtual( m_shellcode_va );
				m_shellcode_va = 0;
			}
		}

		void debug_exception( ) const {
			switch ( m_remote_data.m_status ) {
			case 1:
			{
				logging::print( encrypt( "Target process terminated unexpectedly during module preperation" ) );
			} break;
			case 2:
			{
				logging::print( encrypt( "Target process terminated unexpectedly during execution in RAX" ) );
				logging::print( encrypt( "Exception likely due to corrupted module code." ) );
			} break;
			case 3:
			{
				logging::print( encrypt( "Target process terminated unexpectedly during cleanup" ) );
				logging::print( encrypt( "Exception likely due to corrupted stack frame." ) );
			} break;
			default:
			{
				logging::print( encrypt( "Target process terminated unexpectedly" ) );
			} break;
			}

			if ( m_reflective_mode ) {
				if ( m_remote_data.m_return || m_reflective_data.m_dll_return )
					logging::print( encrypt( "Shellcode Exception Data, Shellcode Return=%i, Reflective Return=%i" ),
						m_remote_data.m_return, m_reflective_data.m_dll_return );
			}
			else {
				if ( m_remote_data.m_return )
					logging::print( encrypt( "Shellcode Exception Data, Shellcode Return=%i" ),
						m_remote_data.m_return );
			}
		}
	};
}
