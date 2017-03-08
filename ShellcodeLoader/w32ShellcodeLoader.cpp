#include "w32ShellcodeLoader.h"

const int SIZE_SHELLCODE_BUFFER = 2048;
const char* MOV_EAX = "\xb8";
const char* CALL_EAX = "\xff\xd0";

LPVOID readShellcode(LPCSTR shellcodeFile) {
	LPVOID shellcodeBuffer = VirtualAlloc(NULL, SIZE_SHELLCODE_BUFFER, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	LPDWORD bytesRead = 0;
	
	HANDLE fHandle = CreateFileA(shellcodeFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fHandle == INVALID_HANDLE_VALUE) {
		printf("Could not open shellcode file.\n");
		ExitProcess(-1);
	}

	if (ReadFile(fHandle, shellcodeBuffer, SIZE_SHELLCODE_BUFFER, bytesRead, NULL) < 1) {
		printf("Could not read shellcode file.\n");
		ExitProcess(-1);
	}

	printf("Successfully read shellcode to 0x%x with size of 0x%x bytes.\n", shellcodeBuffer, strlen((char*)shellcodeBuffer));
	return shellcodeBuffer;
}

void hexdumpShellcode(const void* data, size_t size) {
	//taken from https://gist.github.com/ccbrown/9722406
	printf("--------------------------------------------------------------------------------");
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		}
		else {
			ascii[i % 16] = '.';
		}
		if ((i + 1) % 8 == 0 || i + 1 == size) {
			printf(" ");
			if ((i + 1) % 16 == 0) {
				printf("|  %s \n", ascii);
			}
			else if (i + 1 == size) {
				ascii[(i + 1) % 16] = '\0';
				if ((i + 1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i + 1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
	printf("--------------------------------------------------------------------------------");
}

void exitGracefully() {
	printf("Executed shellcode successfully.\n");
	Sleep(3000);
	exit(0);
}

void writeTrampoline(LPVOID shellcode) {
	void(*p)(void) = exitGracefully;
	printf("Writing trampoline to clean up function 0x%p after shellcode.\n", p);
	int shellcodeSize = strlen((char*)shellcode);
	memcpy(((char*)shellcode + shellcodeSize), MOV_EAX, 2);
	memcpy(((char*)shellcode + shellcodeSize + strlen(MOV_EAX)), &p, sizeof(void*));
	memcpy(((char*)shellcode + shellcodeSize + strlen(MOV_EAX) + sizeof(void*)), CALL_EAX, 2);
}

void executeShellcode(LPVOID shellcode) {
	printf("Executing shellcode...\n");
	__asm {
		mov eax, shellcode;
		jmp eax;
	}
}

int main(int argc, char* argv[]) {

	if (argc != 2) {
		printf("Usage: load_shellcode PATH_TO_SHELLCODE");
		ExitProcess(-1);
	}
	else {
		LPVOID shellcode = readShellcode((LPCSTR)argv[1]);
		hexdumpShellcode((void*)shellcode, strlen((char*)shellcode));
		writeTrampoline(shellcode);
		executeShellcode(shellcode);
	}
}