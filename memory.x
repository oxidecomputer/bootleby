MEMORY {
    FLASH (rx): ORIGIN = 0x10000000, LENGTH = 24K
    DATAFLASH (rw): ORIGIN = 0x10000000 + 24K, LENGTH = 8K

    /*
     * Note: RAM is offset by 0x4000 because the Boot ROM uses that area
     * as scratch space during the skboot calls.
     */
    RAM (rw): ORIGIN = 0x30004000, LENGTH = 4K
    /*
     * Stack is shifted hundreds of kiB away to try to avoid stack clash,
     * since the ROM's RAM usage means we can't simply have stack grow toward
     * unmapped address space.
     *
     * The -32 there is to avoid the transient override section.
     */
    STACK (rw): ORIGIN = 0x30010000, LENGTH = 192K - 32

    /*
     * A/B images start at 64kiB for compatibility with the old bootloader's
     * partition layout.
     */
    IMAGE_A (r): ORIGIN = 0x10000000 + 64K, LENGTH = 256K
    IMAGE_B (r): ORIGIN = 0x10000000 + 64K + 256K, LENGTH = 256K

    /*
     * We only model the ping-pong (committed) pages of the NXP CFPA, not the
     * scratch page that appears 512 bytes lower, because we don't write
     * the CFPA. If that _changes_ we will need to adjust this.
     */
    CFPA (r): ORIGIN = 0x1009E000, LENGTH = 1024

    ROM_TABLE (r): ORIGIN = 0x130010f0, LENGTH = 64

    /*
     * The transient override region is a fixed location in RAM, as specified
     * by the design doc. It is outside of our BSS/data regions.
     */
    OVERRIDE (rw): ORIGIN = 0x3003ffe0, LENGTH = 32
}

/*
 * Note: it is critical for correctness that these symbols
 * 1. Span all of our RAM, including our stack, and
 * 2. Aren't placed at the same address (i.e. LENGTH(RAM) != 0).
 *
 * The former is for functionality reasons, the latter is because of
 * an implementation shortcut taken to save flash space.
 */
__start_of_ram = ORIGIN(RAM);
__end_of_ram = ORIGIN(RAM) + LENGTH(RAM);

SECTIONS {
    .stack_placeholder ORIGIN(STACK) (NOLOAD): ALIGN(8) {
        . += LENGTH(STACK);
        _stack_start = .;
    } > STACK
} INSERT BEFORE .uninit

SECTIONS {
    .rom_table ORIGIN(ROM_TABLE) (NOLOAD): {
        BOOTLOADER_TREE = .;
        . += LENGTH(ROM_TABLE);
    } >ROM_TABLE
    .image_a ORIGIN(IMAGE_A) (NOLOAD): {
        IMAGE_A = .;
        . += LENGTH(IMAGE_A);
    } >IMAGE_A
    .image_b ORIGIN(IMAGE_B) (NOLOAD): {
        IMAGE_B = .;
        . += LENGTH(IMAGE_A);
    } >IMAGE_B
    .override ORIGIN(OVERRIDE) (NOLOAD): {
        TRANSIENT_OVERRIDE = .;
        . += LENGTH(OVERRIDE);
    } >OVERRIDE
    .cfpa ORIGIN(CFPA) (NOLOAD): {
        CFPA = .;
        . += LENGTH(CFPA);
    } >CFPA
} INSERT AFTER .uninit;
