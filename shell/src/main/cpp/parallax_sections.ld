/*
 * Runtime decryption temporarily changes .bitcode from RX to RW. Keep the
 * section on its own 16 KiB pages so that this transition can never remove
 * execute permission from adjacent .text or .plt code. 16 KiB is also a
 * multiple of the legacy Android 4 KiB page size.
 */
SECTIONS
{
  .bitcode ALIGN(0x4000) :
  {
    *(.bitcode)
    *(.bitcode.*)
    . = ALIGN(0x4000);
  }
}
INSERT AFTER .text;
