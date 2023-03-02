MEMORY {
    FLASH (rx): ORIGIN = 0x10000000, LENGTH = 24K
    DATAFLASH (rw): ORIGIN = 0x10000000 + 24K, LENGTH = 8K

    /*
     * Note: RAM is offset by 0x4000 because the Boot ROM uses that area
     * as scratch space during the skboot calls.
     */
    RAM (rw): ORIGIN = 0x30004000, LENGTH = 4K

    /*
     * A/B images start at 64kiB for compatibility with the old bootloader's
     * partition layout.
     */
    IMAGE_A (r): ORIGIN = 0x10000000 + 64K, LENGTH = 256K
    IMAGE_B (r): ORIGIN = 0x10000000 + 64K + 256K, LENGTH = 256K

    ROM_TABLE (r): ORIGIN = 0x130010f0, LENGTH = 64
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
} INSERT AFTER .uninit;
