/*
A limited disassembler that will search for a running Wesnoth process and then diassemble 0x50 bytes starting at 0x7ccd91. 
These instructions are responsible for subtracting gold from a player when recruiting a unit.

The disassembler works by using CreateToolhelp32Snapshot to find the Wesnoth process and the main Wesnoth module. 
Once located, a buffer is created and the module's memory is read into that buffer. The module's memory mainly contains opcodes for instruction. 
Once loaded, we loop through all the bytes in the buffer and disassemble them based off the reference provided by Intel at 
https://software.intel.com/content/www/us/en/develop/download/intel-64-and-ia-32-architectures-sdm-combined-volumes-1-2a-2b-2c-2d-3a-3b-3c-3d-and-4.html

The full explanation for how this code works is available at: https://gamehacking.academy/lesson/39
*/
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

#define START_ADDRESS 0x7ccd91

// The 8 possible operand values
const char modrm_value[8][4] = {
	"eax",
	"ecx",
	"edx",
	"ebx",
	"esp",
	"ebp",
	"esi",
	"edi"
};

// Table 2-2 in the reference document describes how to retrieve the operands from a ModR/M value
int decode_operand(unsigned char* buffer, int location) {
	if (buffer[location] >= 0xC0 && buffer[location] <= 0xFF) {
		printf("%s, %s", modrm_value[buffer[location] % 8], modrm_value[(buffer[location] >> 3) % 8]);
		return 1;
	}
	else if (buffer[location] >= 0x80 && buffer[location] <= 0xBF) {
		DWORD displacement = buffer[location + 1] | (buffer[location + 2] << 8) | (buffer[location + 3] << 16) | (buffer[location + 4] << 24);
		printf("[%s+%x], %s", modrm_value[buffer[location] % 8], displacement, modrm_value[(buffer[location] >> 3) % 8]);
		return 5;
	}
	else if (buffer[location] >= 0x40 && buffer[location] <= 0x7F) {
		printf("[%s+%x], %s", modrm_value[buffer[location] % 8], buffer[location+1], modrm_value[(buffer[location] >> 3) % 8]);
		return 2;
	}

	return 1;
}

int main(int argc, char** argv) {
	HANDLE process_snapshot = 0;
	HANDLE module_snapshot = 0;
	PROCESSENTRY32 pe32 = { 0 };
	MODULEENTRY32 me32;

	DWORD exitCode = 0;

	pe32.dwSize = sizeof(PROCESSENTRY32);
	me32.dwSize = sizeof(MODULEENTRY32);

	// The snapshot code is a reduced version of the example code provided by Microsoft at 
	// https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes
	process_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	Process32First(process_snapshot, &pe32);

	do {
		// Only disassmble the Wesnoth process
		if (wcscmp(pe32.szExeFile, L"wesnoth.exe") == 0) {
			module_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);

			// Retrieve a process handle so that we can read the game's memory
			HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, true, pe32.th32ProcessID);

			Module32First(module_snapshot, &me32);
			do {
				// Wesnoth is made up of many modules. For our example, we only want to scan the main executable module's code
				if (wcscmp(me32.szModule, L"wesnoth.exe") == 0) {
					// Due to the size of the code, dynamically create a buffer after determining the size
					unsigned char* buffer = (unsigned char*)calloc(1, me32.modBaseSize);
					DWORD bytes_read = 0;

					// Read the entire code block into our buffer
					ReadProcessMemory(process, (void*)me32.modBaseAddr, buffer, me32.modBaseSize, &bytes_read);

					DWORD loc = 0;
					unsigned int i = START_ADDRESS - (DWORD)me32.modBaseAddr;
					
					// For each byte in the game's code, attempt to disassmble it
					while (i < START_ADDRESS + 0x50 - (DWORD)me32.modBaseAddr) {
						printf("%x:\t", i + (DWORD)me32.modBaseAddr);
						switch (buffer[i]) {
						case 0x1:
							printf("ADD ");
							i++;
							i += decode_operand(buffer, i);
							break;
						case 0x29:
							printf("SUB ");
							i++;
							i += decode_operand(buffer, i);
							break;
						case 0x74:
							printf("JE ");
							printf("%x", i + (DWORD)me32.modBaseAddr + 2 + buffer[i + 1]);
							i += 2;
							break;
						case 0x80:
							printf("CMP ");
							i++;
							i += decode_operand(buffer, i);
							break;
						case 0x8D:
							printf("LEA ");
							i++;
							i += decode_operand(buffer, i);
							break;
						case 0x8B:
						case 0x89:
							printf("MOV ");
							i++;
							i += decode_operand(buffer, i);
							break;
						case 0xE8:
							printf("CALL ");
							i++;
							loc = buffer[i] | (buffer[i+1] << 8) | (buffer[i+2] << 16) | (buffer[i+3] << 24);
							printf("%x", loc + (i + (DWORD)me32.modBaseAddr) + 4);
							i += 4;
							break;
						default:
							printf("%x", buffer[i]);
							i++;
							break;
						}

						printf("\n");
					}

					free(buffer);
					break;
				}

			} while (Module32Next(module_snapshot, &me32));

			CloseHandle(process);
			break;
		}
	} while (Process32Next(process_snapshot, &pe32));

	return 0;
}
