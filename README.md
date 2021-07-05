# Disassembler

A limited disassembler that will search for a running Wesnoth process and then diassemble 0x50 bytes starting at 0x7ccd91. These instructions are responsible for subtracting gold from a player when recruiting a unit.

The disassembler works by using CreateToolhelp32Snapshot to find the Wesnoth process and the main Wesnoth module. Once located, a buffer is created and the module's memory is read into that buffer. The module's memory mainly contains opcodes for instruction. Once loaded, we loop through all the bytes in the buffer and disassemble them based off the reference provided by Intel at https://software.intel.com/content/www/us/en/develop/download/intel-64-and-ia-32-architectures-sdm-combined-volumes-1-2a-2b-2c-2d-3a-3b-3c-3d-and-4.html

The full explanation for how this code works is available at: https://gamehacking.academy/lesson/39
