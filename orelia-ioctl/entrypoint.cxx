#include <impl/includes.h>

struct dpc_context {
	std::uint64_t image_base;
	std::uint64_t entry_point;
	std::uint32_t image_size;
	std::uint32_t status;
};

/* Runs inside the mapper's DPC on an isolated core (IRQL 2). Everything here
 * is nonpaged: PEB/ntoskrnl base lookup, the export-table walk and the driver
 * object creation have always executed at this IRQL for this driver.
 *
 * A WORK_QUEUE_ITEM handoff to a PASSIVE worker was tried and bugchecked 0xE4
 * (WORKER_INVALID): the queue rejects an item whose storage belongs to an
 * image the kernel never loaded as a driver. The one thing that genuinely
 * cannot run at IRQL 2 is DbgPrintEx's string conversion, so that is handled
 * where it lives: device.h prints literals only, and nt::dbg_print refuses
 * %wZ/%Z/%S/%C/%ls/%lc above PASSIVE. */
nt_status_t entry_point( void* a1, dpc_context* ctx ) {
	if ( !nt::g_resolver.setup( ) ) {
		ctx->status = 0xE0000001;
		return nt_status_t::not_supported;
	}

	if ( !mm::g_paging.setup( ) ) {
		ctx->status = 0xE0000002;
		return nt_status_t::not_supported;
	}

	device::init_ioctl_name( );
	auto result = nt::create_driver( dispatch::intialize_driver );
	ctx->status = static_cast< std::uint32_t >( result );
	return result;
}
