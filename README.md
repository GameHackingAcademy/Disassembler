# Disassembler

Referenced in https://gamehacking.academy/lesson/7/4.

A limited disassembler that will search for a running Wesnoth process and then disassemble 0x50 bytes starting at 0x7ccd91. These instructions are responsible for subtracting gold from a player when recruiting a unit.

The disassembler works by using CreateToolhelp32Snapshot to find the Wesnoth process and the main Wesnoth module. Once it is located, a buffer is created and the module's memory is read into that buffer. The module's memory mainly contains opcodes for instruction. Once they are loaded, we loop through all the bytes in the buffer and disassemble them based on the reference provided by Intel here.
