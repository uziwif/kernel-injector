#define ioctl_device L"\\Device\\Steam64"
#define ioctl_dos_device L"\\GLOBAL??\\Steam64"
#define irp_mj_create 0x00
#define irp_mj_close 0x02
#define irp_mj_device_control 0x0E
#define irp_mj_maximum_function 0x1B
#define irp_mj_cleanup 18
#define do_device_initializing 0x00000080
#define do_buffered_io 0x00000004
#define file_device_secure_open 0x00000100

namespace device {
	unicode_string_t device_name;
	unicode_string_t dos_device_name;

	void init_ioctl_name( ) {
		nt::rtl_init_unicode_string( &device::device_name, ioctl_device );
		nt::rtl_init_unicode_string( &device::dos_device_name, ioctl_dos_device );

		/* Literal formats only. This runs in the mapper's DPC at IRQL 2,
		 * where DbgPrintEx cannot convert %wZ - the conversion is paged
		 * and bugchecks 0xA in RtlpIsUtf8Process. The names are compile-
		 * time constants, so printing them literally loses nothing. */
		nt::dbg_print( "[orelia] device name: \\Device\\Steam64\n" );
		nt::dbg_print( "[orelia] dos device name: \\GLOBAL??\\Steam64\n" );
	}
}

#include <workspace/device/controller/controller.hxx>
#include <workspace/device/dispatch/dispatch.hxx>