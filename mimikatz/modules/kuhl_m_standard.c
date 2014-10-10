/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kuhl_m_standard.h"

const KUHL_M_C kuhl_m_c_standard[] = {
	//{kuhl_m_standard_test,		L"test",	L"Test routine (you don\'t want to see this !)"},
	{kuhl_m_standard_exit,		L"exit",	L"Quit mimikatz"},
	{kuhl_m_standard_cls,		L"cls",		L"Clear screen (doesn\'t work with redirections, like PsExec)"},
	{kuhl_m_standard_answer,	L"answer",	L"Answer to the Ultimate Question of Life, the Universe, and Everything"},
	{kuhl_m_standard_coffee,	L"coffee",	L"Please, make me a coffee!"},
	{kuhl_m_standard_sleep,		L"sleep",	L"Sleep an amount of milliseconds"},
	{kuhl_m_standard_log,		L"log",		L"Log mimikatz input/output to file"},
	{kuhl_m_standard_base64,	L"base64",	L"Switch file output/base64 output"},
	{kuhl_m_standard_version,	L"version",	L"Display some version informations"},
	{kuhl_m_standard_cd,		L"cd",		L"Change or display current directory"},
	{kuhl_m_standard_markruss,	L"markruss",L"Change or display current directory"},
};
const KUHL_M kuhl_m_standard = {
	L"standard",	L"Standard module",	L"Basic commands (does not require module name)",
	ARRAYSIZE(kuhl_m_c_standard), kuhl_m_c_standard, NULL, NULL
};
/*
NTSTATUS kuhl_m_standard_test(int argc, wchar_t * argv[])
{
	return STATUS_SUCCESS;
}
*/
NTSTATUS kuhl_m_standard_exit(int argc, wchar_t * argv[])
{
	kprintf(L"Bye!\n");
	return STATUS_FATAL_APP_EXIT;
}

NTSTATUS kuhl_m_standard_cls(int argc, wchar_t * argv[])
{
	HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	COORD coord = {0, 0};
	DWORD count;
	CONSOLE_SCREEN_BUFFER_INFO csbi;

	GetConsoleScreenBufferInfo(hStdOut, &csbi);
	FillConsoleOutputCharacter(hStdOut, L' ', csbi.dwSize.X * csbi.dwSize.Y, coord, &count);
	SetConsoleCursorPosition(hStdOut, coord);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_standard_answer(int argc, wchar_t * argv[])
{
	kprintf(L"42.\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_standard_coffee(int argc, wchar_t * argv[])
{
	kprintf(L"\n    ( (\n     ) )\n  .______.\n  |      |]\n  \\      /\n   `----'\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_standard_sleep(int argc, wchar_t * argv[])
{
	DWORD dwMilliseconds = argc ? wcstoul(argv[0], NULL, 0) : 1000;
	kprintf(L"Sleep : %u ms... ", dwMilliseconds);
	Sleep(dwMilliseconds);
	kprintf(L"End !\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_standard_log(int argc, wchar_t * argv[])
{
	PCWCHAR filename = (kull_m_string_args_byName(argc, argv, L"stop", NULL, NULL) ? NULL : (argc ? argv[0] : MIMIKATZ_DEFAULT_LOG));
	kprintf(L"Using \'%s\' for logfile : %s\n", filename, kull_m_output_file(filename) ? L"OK" : L"KO");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_standard_base64(int argc, wchar_t * argv[])
{
	kprintf(L"isBase64Intercept was    : %s\n", isBase64Intercept ? L"true" : L"false");
	isBase64Intercept = !isBase64Intercept;
	kprintf(L"isBase64Intercept is now : %s\n", isBase64Intercept ? L"true" : L"false");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_standard_version(int argc, wchar_t * argv[])
{
	BOOL isWow64;
	#ifdef _M_X64
	isWow64 = TRUE;
	#else
	if(IsWow64Process(GetCurrentProcess(), &isWow64))
	#endif
	{
		kprintf(
			L"\n" MIMIKATZ L" " MIMIKATZ_VERSION L" (arch " MIMIKATZ_ARCH L")\n"
			L"NT     -  Windows NT %u.%u build %u (arch x%s)\n",
			MIMIKATZ_NT_MAJOR_VERSION, MIMIKATZ_NT_MINOR_VERSION, MIMIKATZ_NT_BUILD_NUMBER, isWow64 ? L"64" : L"86"
			);
	}
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_standard_cd(int argc, wchar_t * argv[])
{
	wchar_t * buffer;
	if(kull_m_file_getCurrentDirectory(&buffer))
	{
		if(argc)
			kprintf(L"Old: ");
		kprintf(L"%s\n", buffer);
		LocalFree(buffer);
	}
	else PRINT_ERROR_AUTO(L"kull_m_file_getCurrentDirectory");

	if(argc)
	{
		if(SetCurrentDirectory(argv[0]))
		{
			if(kull_m_file_getCurrentDirectory(&buffer))
			{
				kprintf(L"New: %s\n", buffer);
				LocalFree(buffer);
			}
			else PRINT_ERROR_AUTO(L"kull_m_file_getCurrentDirectory");
		}
		else PRINT_ERROR_AUTO(L"SetCurrentDirectory");
	}
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_standard_markruss(int argc, wchar_t * argv[])
{
	kprintf(L"Sorry you guys don\'t get it.\n");
	return STATUS_SUCCESS;
}