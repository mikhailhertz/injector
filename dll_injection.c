#undef UNICODE
#include <windows.h>

// TODO: проверять является ли строка числом
int atoi(const char * string) // преобразует строку в int
{
	int value = 0;
	while (*string) // пока не дошли до конца строки ('\0')
	{
		value = value * 10 + (*string++ - '0'); // вычитая '0' из ascii символа цифры получаем двоичное значение цифры
	}
	return value;
}

int main()
{
	char buffer[255];
	char * pid_str = buffer;
	char * dll_path = buffer;
	DWORD n_characters_rw = 0; // число считанных/записанных символов
	BOOL status = FALSE;
	HANDLE process_handle = NULL;
	HANDLE thread_handle = NULL;
	FARPROC loadlibrary_ptr = NULL;
	LPVOID target_ptr = NULL;
	status = ReadConsole(GetStdHandle(STD_INPUT_HANDLE), buffer, 255, &n_characters_rw, NULL);
	if (status == FALSE)
	{
		goto cleanup;
	}
	buffer[n_characters_rw - 2] = '\0'; // последние 2 символа - '\r', '\n', меняем '\r' на '\0'
	while (*dll_path != ' ') // ищем пробел, изначально dll_path указывает в начало buffer
	{
		if (*dll_path == '\0') // если дошли до конца строки - ошибка
		{
			SetLastError(ERROR_INVALID_PARAMETER);
			goto cleanup;
		}
		else
		{
			dll_path += 1;
		}
	}
	*dll_path = '\0'; // заменяем пробел на '\0'
	dll_path += 1; // перемещаем указатель на начало строки
	DWORD pid = atoi(pid_str);
	process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (process_handle == NULL)
	{
		goto cleanup;
	}
	loadlibrary_ptr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"); /* адрес LoadLibraryA одинаковый...
	                                                                ...у всех программ т.к. kernel32.dll всегда загружается в один и тот же адрес */
	if (loadlibrary_ptr == NULL)
	{
		goto cleanup;
	}
	target_ptr = VirtualAllocEx(process_handle, NULL, strlen(dll_path), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (target_ptr == NULL)
	{
		goto cleanup;
	}
	status = WriteProcessMemory(process_handle, target_ptr, dll_path, strlen(dll_path), NULL);
	if (status == FALSE)
	{
		goto cleanup;
	}
	DWORD tid = 0;
	thread_handle = CreateRemoteThread(process_handle, NULL, 0, (LPTHREAD_START_ROUTINE)loadlibrary_ptr, target_ptr, 0, &tid); /* создаем поток...
																       ... выполняющий LoadLibraryA с параметром target_ptr, в который записан путь к dll */
	if (thread_handle == NULL)
	{
		goto cleanup;
	}
cleanup:
	if (thread_handle != NULL)
	{
		WaitForSingleObject(thread_handle, INFINITE);
	}
	if (target_ptr != NULL)
	{
		VirtualFreeEx(process_handle, target_ptr, strlen(dll_path), MEM_RELEASE);
	}
	if (thread_handle != NULL)
	{
		CloseHandle(thread_handle);
	}
	if (process_handle != NULL)
	{
		CloseHandle(process_handle);
	}
	DWORD error_id = GetLastError();
	if (error_id != 0) // если произошла ошибка - выводим соответствующее ей сообщение на экран
	{
		MessageBeep(MB_ICONERROR);
		LPSTR error_string = NULL;
		size_t size = FormatMessageA(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, error_id, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&error_string, 0, NULL);
		WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), error_string, size, &n_characters_rw, NULL);
		LocalFree(error_string);
		DWORD unused;
		ReadConsole(GetStdHandle(STD_INPUT_HANDLE), &unused, 1, &unused, NULL); // ждем ввод
		return EXIT_FAILURE;
	}
	else
	{
		MessageBeep(MB_OK);
		return EXIT_SUCCESS;
	}
}