OUTPUT_ARCH(aarch64)
ENTRY(_start)

KERNEL_START 	= 0x92000000;
KERNEL_LENGTH   = 0x01000000; # Arbitrarily chosen

STACK_SIZE 		= 0x8000;

MEMORY
{
	KERNELRAM	(rwx) : ORIGIN = KERNEL_START, LENGTH = KERNEL_LENGTH
}


SECTIONS
{
	. = KERNEL_START;

	.start : {
		__text_start_start = .;
		*(.text.start);
		*(.text.init);
		. = ALIGN(128);
		__text_start_end = .;
	} > KERNELRAM

	.text :
	{
		__text_start = .;
		. = ALIGN(128);
		KEEP(*(.text.header));
		. = ALIGN(128);
		*(.text.reset);
		*(.text*);
		__text_end = .;
		. = ALIGN(16);
	} > KERNELRAM

	#. = ALIGN(2K);
	#.vectors : {
	#	__vectors_start = .;
	#
	#	KEEP(*(.vectors.current_el.sp_el0.synchronous))
	#	. = ALIGN(0x80);
	#	KEEP(*(.vectors.current_el.sp_el0.irq))
	#	. = ALIGN(0x80);
	#	KEEP(*(.vectors.current_el.sp_el0.fiq))
	#	. = ALIGN(0x80);
	#	KEEP(*(.vectors.current_el.sp_el0.serror))
	#	. = ALIGN(0x80);
#
	#	KEEP(*(.vectors.current_el.sp_elx.synchronous))
	#	. = ALIGN(0x80);
	#	KEEP(*(.vectors.current_el.sp_elx.irq))
	#	. = ALIGN(0x80);
	#	KEEP(*(.vectors.current_el.sp_elx.fiq))
	#	. = ALIGN(0x80);
	#	KEEP(*(.vectors.current_el.sp_elx.serror))
	#	. = ALIGN(0x80);
#
	#	KEEP(*(.vectors.lower_el.a64.synchronous))
	#	. = ALIGN(0x80);
	#	KEEP(*(.vectors.lower_el.a64.irq))
	#	. = ALIGN(0x80);
	#	KEEP(*(.vectors.lower_el.a64.fiq))
	#	. = ALIGN(0x80);
	#	KEEP(*(.vectors.lower_el.a64.serror))
	#	. = ALIGN(0x80);
#
	#	KEEP(*(.vectors.lower_el.a32.synchronous))
	#	. = ALIGN(0x80);
	#	KEEP(*(.vectors.lower_el.a32.irq))
	#	. = ALIGN(0x80);
	#	KEEP(*(.vectors.lower_el.a32.fiq))
	#	. = ALIGN(0x80);
	#	KEEP(*(.vectors.lower_el.a32.serror))
	#	. = ALIGN(0x80);
	#
	#	__vectors_end = .;
#
	#	. = ALIGN(1K);
	#} > KERNELRAM

    .rodata : {
		. = ALIGN(16);
		__rodata_start = .;

		*(.rodata .rodata.*);

		. = ALIGN(16);
		__rodata_end = .;
	} > KERNELRAM

	.data : {
		. = ALIGN(16);
		__data_start = .;

		KEEP(*(.data*));
		KEEP(*(.tdata .tdata.*));
		KEEP(*(.tbss .tbss.*));
		KEEP(*(.tcommon));

		. = ALIGN(16);
		__data_end = .;
	} > KERNELRAM

	__end = .;

	.bss (NOLOAD) :
	{
		. = ALIGN(16);
		__bss_start = .;

		*(.bss .bss.*)
		*(COMMON)

		. = ALIGN(16);
		__bss_end = .;
	} > KERNELRAM

	.stack (NOLOAD) : {
		__stack_bottom = .;
		. = . + STACK_SIZE;
		__stack_top = .;
	} > KERNELRAM

	/DISCARD/ : {
		*(.interp)
	}
}
