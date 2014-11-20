/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kuhl_m_minesweeper.h"

const KUHL_M_C kuhl_m_c_minesweeper[] = {
	{kuhl_m_minesweeper_infos,	L"infos",	L"infos"},
};
const KUHL_M kuhl_m_minesweeper = {
	L"minesweeper",	L"MineSweeper module", NULL,
	ARRAYSIZE(kuhl_m_c_minesweeper), kuhl_m_c_minesweeper, NULL, NULL
};

#ifdef _M_X64
BYTE PTRN_WIN6_Game_SafeGetSingleton[] = {0x48, 0x89, 0x44, 0x24, 0x70, 0x48, 0x85, 0xc0, 0x74, 0x0a, 0x48, 0x8b, 0xc8, 0xe8};
LONG OFFS_WIN6_ToG	= -21;
#elif defined _M_IX86
BYTE PTRN_WIN6_Game_SafeGetSingleton[] = {0x84, 0xc0, 0x75, 0x07, 0x6a, 0x67, 0xe8};
LONG OFFS_WIN6_ToG	= 12;
#endif

const CHAR DISP_MINESWEEPER[] = "012345678.F? !!";
NTSTATUS kuhl_m_minesweeper_infos(int argc, wchar_t * argv[])
{
	DWORD dwPid, r, c;
	HANDLE hProcess;
	PEB Peb;
	PIMAGE_NT_HEADERS pNtHeaders;
	PVOID G = NULL;
	STRUCT_MINESWEEPER_GAME Game;
	STRUCT_MINESWEEPER_BOARD Board;
	KULL_M_MEMORY_SEARCH sMemory = {{{NULL, NULL}, 0}, NULL};
	KULL_M_MEMORY_HANDLE hLocalMemory = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aRemote = {NULL, NULL}, aBuffer = {PTRN_WIN6_Game_SafeGetSingleton, &hLocalMemory};
	BOOL bAlloc = FALSE;
	LONG offsetTemp = 0;
	CHAR ** field = NULL;

	if(kull_m_process_getProcessIdForName(L"minesweeper.exe", &dwPid))
	{
		if(hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, dwPid))
		{
			if(kull_m_memory_open(KULL_M_MEMORY_TYPE_PROCESS, hProcess, &aRemote.hMemory))
			{
				if(kull_m_process_peb(aRemote.hMemory, &Peb, FALSE))
				{
					aRemote.address = Peb.ImageBaseAddress;
					if(kull_m_process_ntheaders(&aRemote, &pNtHeaders))
					{
						sMemory.kull_m_memoryRange.kull_m_memoryAdress.hMemory = aRemote.hMemory;
						sMemory.kull_m_memoryRange.kull_m_memoryAdress.address = (LPVOID) pNtHeaders->OptionalHeader.ImageBase;
						sMemory.kull_m_memoryRange.size = pNtHeaders->OptionalHeader.SizeOfImage;
						if(kull_m_memory_search(&aBuffer, sizeof(PTRN_WIN6_Game_SafeGetSingleton), &sMemory, TRUE))
						{
							aRemote.address = (PBYTE) sMemory.result + OFFS_WIN6_ToG;
#ifdef _M_X64
							aBuffer.address = &offsetTemp;
							if(kull_m_memory_copy(&aBuffer, &aRemote, sizeof(LONG)))
							{
								aRemote.address = (PBYTE) aRemote.address + 1 + sizeof(LONG) + offsetTemp;
#elif defined _M_IX86
							aBuffer.address = &aRemote.address;
							if(kull_m_memory_copy(&aBuffer, &aRemote, sizeof(PVOID)))
							{
#endif
								aBuffer.address = &G;
								if(kull_m_memory_copy(&aBuffer, &aRemote, sizeof(PVOID)))
								{
									aRemote.address = G;
									aBuffer.address = &Game;
									if(kull_m_memory_copy(&aBuffer, &aRemote, sizeof(STRUCT_MINESWEEPER_GAME)))
									{
#ifdef _M_IX86
										if(MIMIKATZ_NT_BUILD_NUMBER >= KULL_M_WIN_MIN_BUILD_7)
											Game.pBoard = Game.pBoard_WIN7x86;
#endif
										aRemote.address = Game.pBoard;
										aBuffer.address = &Board;

										if(kull_m_memory_copy(&aBuffer, &aRemote, sizeof(STRUCT_MINESWEEPER_BOARD)))
										{
											kprintf(L"Field : %u r x %u c\nMines : %u\n\n", Board.cbRows, Board.cbColumns, Board.cbMines);
											if(field = (CHAR **) LocalAlloc(LPTR, sizeof(CHAR *) * Board.cbRows))
											{
												for(r = 0, bAlloc = TRUE; (r < Board.cbRows) && bAlloc; r++)
												{
													if(field[r] = (CHAR *) LocalAlloc(LPTR, sizeof(CHAR) * Board.cbColumns))
														bAlloc &= TRUE;
													else PRINT_ERROR(L"Memory C (R = %u)\n", r);
												}
											}
											else PRINT_ERROR(L"Memory R\n");

											if(bAlloc)
											{
												kuhl_m_minesweeper_infos_parseField(aRemote.hMemory, Board.ref_visibles, field, TRUE);
												kuhl_m_minesweeper_infos_parseField(aRemote.hMemory, Board.ref_mines, field, FALSE);
												for(r = 0; r < Board.cbRows; r++)
												{
													kprintf(L"\t");
													for(c = 0; c < Board.cbColumns; c++)
														kprintf(L"%C ", field[r][c]);
													kprintf(L"\n");
												}
											}

											if(field)
											{
												for(r = 0; r < Board.cbRows; r++)
												{
													if(field[r])
														LocalFree(field[r]);
												}
												LocalFree(field);
											}
										}
										else PRINT_ERROR(L"Board copy\n");
									}
									else PRINT_ERROR(L"Game copy\n");
								}
								else PRINT_ERROR(L"G copy\n");
							}
							else PRINT_ERROR(L"Global copy\n");
						}
						else PRINT_ERROR(L"Search is KO\n");
						LocalFree(pNtHeaders);
					}
					else PRINT_ERROR(L"Minesweeper NT Headers\n");
				}
				else PRINT_ERROR(L"Minesweeper PEB\n");
				kull_m_memory_close(aRemote.hMemory);
			}
			CloseHandle(hProcess);
		}
		else PRINT_ERROR_AUTO(L"OpenProcess");
	}
	else PRINT_ERROR(L"No MineSweeper in memory!\n");

	return STATUS_SUCCESS;
}


void kuhl_m_minesweeper_infos_parseField(PKULL_M_MEMORY_HANDLE hMemory, PSTRUCT_MINESWEEPER_REF_ELEMENT base, CHAR ** field, BOOL isVisible)
{
	STRUCT_MINESWEEPER_REF_ELEMENT ref_first_element;
	PSTRUCT_MINESWEEPER_REF_ELEMENT * ref_columns_elements;
	STRUCT_MINESWEEPER_REF_ELEMENT ref_column_element;	
	DWORD c, r, szFinalElement = isVisible ? sizeof(DWORD) : sizeof(BYTE);
	KULL_M_MEMORY_HANDLE hLocalMemory = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aRemote = {base, hMemory}, aLocal = {&ref_first_element, &hLocalMemory};

	if(kull_m_memory_copy(&aLocal, &aRemote, sizeof(STRUCT_MINESWEEPER_REF_ELEMENT)))
	{
		if(ref_columns_elements = (PSTRUCT_MINESWEEPER_REF_ELEMENT *) LocalAlloc(LPTR, sizeof(PSTRUCT_MINESWEEPER_REF_ELEMENT) * ref_first_element.cbElements))
		{
			aLocal.address = ref_columns_elements;
			aRemote.address = ref_first_element.elements;
			
			if(kull_m_memory_copy(&aLocal, &aRemote, ref_first_element.cbElements * sizeof(PSTRUCT_MINESWEEPER_REF_ELEMENT)))
			{
				for(c = 0; c < ref_first_element.cbElements; c++)
				{
					aLocal.address = &ref_column_element;
					aRemote.address = ref_columns_elements[c];
					if(kull_m_memory_copy(&aLocal, &aRemote, sizeof(STRUCT_MINESWEEPER_REF_ELEMENT)))
					{
						if(aLocal.address = LocalAlloc(LPTR, szFinalElement * ref_column_element.cbElements))
						{
							aRemote.address = ref_column_element.elements;
							if(kull_m_memory_copy(&aLocal, &aRemote, szFinalElement * ref_column_element.cbElements))
							{
								for(r = 0; r < ref_column_element.cbElements; r++)
								{
									if(isVisible)
										field[r][c] = DISP_MINESWEEPER[((DWORD *)(aLocal.address))[r]];
									else if(((BYTE *)(aLocal.address))[r])
										field[r][c] = '*';
								}
							}
							else PRINT_ERROR(L"Unable to read elements from column: %u\n", c);
							LocalFree(aLocal.address);
						}
					}
					else PRINT_ERROR(L"Unable to read references from column: %u\n", c);
				}
			}
			else PRINT_ERROR(L"Unable to read references\n");
			LocalFree(ref_columns_elements);
		}
	}
	else PRINT_ERROR(L"Unable to read first element\n");		
}