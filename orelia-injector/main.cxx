#include <impl/includes.h>

int __cdecl main( int argc, char** argv ) {
	const char* dll_path = nullptr;

	if ( argc < 2 ) {
		logging::print( encrypt( "Error: Missing parameters, auto resorting to orelia-internal.dll" ) );
		dll_path = "orelia-internal.dll";
	}
	else {
		dll_path = argv[ 1 ];
	}

	setvbuf( stdout , nullptr , _IONBF , 0 );
	SetConsoleTitleA( encrypt( "orelia-injector" ) );
	SetUnhandledExceptionFilter( exception::exception_filter );

	if ( !g_driver->setup( ) )
		return std::getchar( );

	if ( !g_driver->attach( target_process ) ) {
		logging::print( encrypt( "Failed to attach process.\n" ) );
		g_driver->unload( );
		return std::getchar( );
	}

	bool reflective_mode = false;
	if ( argc >= 3 && strstr( argv[ 2 ], encrypt( "--reflective" ) ) )
		reflective_mode = true;

	auto injector = std::make_shared< injector::c_injector >( reflective_mode );
	if ( !injector->map( dll_path ) ) {
		injector->cleanup( );
		g_driver->unload( );
		return std::getchar( );
	}

	if ( !injector->hook( ) ) {
		injector->cleanup( );
		g_driver->unload( );
		return std::getchar( );
	}

	g_driver->unload( );
	return std::getchar( );
}