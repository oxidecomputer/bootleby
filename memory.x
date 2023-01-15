MEMORY {
    FLASH (rx): ORIGIN = 0x10000000, LENGTH = 32K
    RAM (rw): ORIGIN = 0x30004000, LENGTH = 64K

    IMAGE_A (r): ORIGIN = 0x10000000 + 32K, LENGTH = 299K
    IMAGE_B (r): ORIGIN = 0x10000000 + 32K + 299K, LENGTH = 299K

    ROM_TABLE (r): ORIGIN = 0x130010f0, LENGTH = 64
}

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
