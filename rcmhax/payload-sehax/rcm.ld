PAYLOADRAM_START 	= 0x40020000;
PAYLOADRAM_LENGTH   = 0x00030000; # Arbitrarily chosen

STACK_SIZE 		= 0x00008000;

MEMORY
{
	PAYLOADRAM	(rwx) : ORIGIN = PAYLOADRAM_START, LENGTH = PAYLOADRAM_LENGTH
}


SECTIONS
{
	. = PAYLOADRAM_START;

	.start : {
		__text_start_start = .;
		*(.text.start);
		*(.text.init);
		. = ALIGN(16);
		__text_start_end = .;
	} > PAYLOADRAM

	.text :
	{
		__text_start = .;
		. = ALIGN(16);
		*(.text*);
		__text_end = .;
		. = ALIGN(16);
	} > PAYLOADRAM

    .rodata : {
		. = ALIGN(16);
		__rodata_start = .;

		*(.rodata .rodata.*);

		. = ALIGN(16);
		__rodata_end = .;
	} > PAYLOADRAM

	.data : {
		. = ALIGN(16);
		__data_start = .;

		KEEP(*(.data*));
		KEEP(*(.tdata .tdata.*));
		KEEP(*(.tbss .tbss.*));
		KEEP(*(.tcommon));

		. = ALIGN(16);
		__data_end = .;
	} > PAYLOADRAM

	__end = .;

	.bss (NOLOAD) :
	{
		. = ALIGN(16);
		__bss_start = .;

		*(.bss .bss.*)
		*(COMMON)

		. = ALIGN(16);
		__bss_end = .;
	} > PAYLOADRAM

	.stack (NOLOAD) : {
		__stack_bottom = .;
		. = . + STACK_SIZE;
		__stack_top = .;
	} > PAYLOADRAM

	/DISCARD/ : {
		*(.interp)
	}
}
