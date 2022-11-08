

int main(int argc, char** argv) {
	__asm {
		// нахождение базового адреса kernel32.dll
		xor ecx, ecx
		mov eax, fs: [ecx + 0x30] ; EAX = PEB // установка указателя на PEB
		mov eax, [eax + 0xc]; EAX = PEB->Ldr  //перемещение на указатель Ldr в структуре
		mov esi, [eax + 0x14]; ESI = PEB->Ldr.InMemOrder  //список модулей
		lodsd; EAX = Second module     
		xchg eax, esi; EAX = ESI, ESI = EAX // перемещение во второй  и третий модули
		lodsd; EAX = Third(kernel32)  // 3 модуль kernel32.dll
		mov ebx, [eax + 0x10]; EBX = Base address
		//нахождение таблицы экспорта
		mov edx, [ebx + 0x3c]; EDX = DOS->e_lfanew //перемещение на указатель e_lfanew
		add edx, ebx; EDX = PE Header
		mov edx, [edx + 0x78]; EDX = Offset export table  //нахождение DataDirectory для экспорта
		add edx, ebx; EDX = Export table //находимся в таблице экспорта
		mov esi, [edx + 0x20]; ESI = Offset names table //чтобы получить имена функций
		add esi, ebx; ESI = Names table
		xor ecx, ecx; EXC = 0

		Get_Function:
		// Поиск имени функции GetProcAddress
		inc ecx; Increment the ordinal  // увеличение регистра ecx
			lodsd; Get name offset //помещает смещение функции
			add eax, ebx; Get function name
			cmp dword ptr[eax], 0x50746547; GetP
			jnz Get_Function //проверяю до тех пор пока не найду нужный указатель
			cmp dword ptr[eax + 0x4], 0x41636f72; rocA
			jnz Get_Function
			cmp dword ptr[eax + 0x8], 0x65726464; ddre
			jnz Get_Function
			// поиск адреса функции GetProcAddress
			mov esi, [edx + 0x24]; ESI = Offset ordinals // Находим смещение AddressOfNameOrdinals
			add esi, ebx; ESI = Ordinals table
			mov cx, [esi + ecx * 2]; CX = Number of function // получение порядкового номера адреса функции
			dec ecx //уменьшается число так как порядкого номера начинаются с 0
			mov esi, [edx + 0x1c]; ESI = Offset address table // по данному смещению находится AddressOfFunctions указатель на массив указателей функций
			add esi, ebx; ESI = Address table
			mov edx, [esi + ecx * 4]; EDX = Pointer(offset) //esi указывает на начало массива, смещение происходит по 4 байта
			add edx, ebx; EDX = GetProcAddress
			//нахождение адреса функции LoadLibrary
			xor ecx, ecx; ECX = 0
			push ebx; Kernel32 base address
			push edx; GetProcAddress
			push ecx; 0
			push 0x41797261; aryA
			push 0x7262694c; Libr
			push 0x64616f4c; Load // Помещение в стек строки "LoadLibraryA\0"
			push esp; "LoadLibrary"
			push ebx; Kernel32 base address
			call edx; GetProcAddress(LL) // Вызов функции
			//загрузка библиотеки advapi32.dll
			add esp, 0xc; pop "LoadLibrary"
			pop ecx; ECX = 0
			push eax; EAX = LoadLibrary
			push ecx; 0
			push 0x6c6c642e;.dll
			push 0x32336970; pi32
			push 0x61766441; Adva
			push esp; "Advapi32.dll"
			call eax; LoadLibrary("Advapi32.dll")
			//получение адреса функции RegDeleteKeyVakueA
			add esp, 0x10; Clean stack
			mov edx, [esp + 0x4]; EDX = GetProcAddress //помещение в регистр edx адрес функции GetProcAdress
			xor ecx, ecx; ECX = 0
			push ecx
			xor ecx, ecx; ECX = 0 //нужно вызвать GetProcAddress(advapi32.dll, «RegDeleteKeyValueA»)
			mov cx, 0x4165; eA
			push ecx
			push 0x756C6156; Valu
			push 0x79654B65; eKey
			push 0x74656C65; elet
			push 0x44676552; RegD
			push esp; "RegDeleteKeyValueA"
			push eax; Advapi32.dll address
			call edx; GetProc(RegDeleteKeyValueA)

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
			//Получение адреса функции ExitProcess
			add esp, 0x1C; Clean stack
			pop edx; GetProcAddress //получение данных которые были скопированны вначале
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
	}
	return 1;
}