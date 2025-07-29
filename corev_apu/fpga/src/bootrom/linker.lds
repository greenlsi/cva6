ENTRY(main)

SECTIONS
{
    ROM_BASE = 0x10000; /* ... but actually position independent */

    . = ROM_BASE;

    .text.init : { *(.text.init) }

    .text : ALIGN(0x100) {
    _TEXT_START_ = .;
        *(.text)
    _TEXT_END_ = .;
    }

    .data : ALIGN(0x100) {
    _DATA_START_ = .;
        *(.data)
    _DATA_END_ = .;
    }

    PROVIDE(_data = ADDR(.data));
    PROVIDE(_data_lma = LOADADDR(.data));
    PROVIDE(_edata = .);

    .bss : ALIGN(0x100) {
    _BSS_START_ = .;
        *(.bss)
    _BSS_END_ = .;
    }

    .rodata : ALIGN(0x100) {
    _RODATA_START_ = .;
        *(.rodata)
        *(.dtb*)
        *(.rodata*)
    _RODATA_END_ = .;
    }


    /* # Sanctum params */
    /* ================ */
    . = 0x801ff000; /* the last page before the payload */

   sanctum_section : ALIGN(0x10) {
        /* manufacturer public key (32 bytes) */
        PROVIDE(sanctum_m_public_key = .);
        . += 0x20;

        /* device public key (32 bytes) */
        PROVIDE(sanctum_dev_public_key = .);
        . += 0x20;

        /* device secret key (64 bytes) */
        PROVIDE(sanctum_dev_secret_key = .);
        . += 0x40;

        /* security monitor hash (64 bytes) */
        PROVIDE(sanctum_sm_hash = .);
        . += 0x40;

        /* security monitor public key (32 bytes) */
        PROVIDE(sanctum_sm_public_key = .);
        . += 0x20;

        /* security monitor secret key (64 bytes) */
        PROVIDE(sanctum_sm_secret_key = .);
        . += 0x40;

        /* security monitor signature (64 bytes) */
        PROVIDE(sanctum_sm_signature = .);
        . += 0x40;
    }
}
