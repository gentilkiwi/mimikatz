/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "../modules/kull_m_process.h"

const KUHL_M kuhl_m_minesweeper;

NTSTATUS kuhl_m_minesweeper_infos(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_minesweeper_bsod(int argc, wchar_t * argv[]);

typedef struct _STRUCT_MINESWEEPER_REF_ELEMENT {
	DWORD cbElements;
	DWORD unk0;
	DWORD unk1;
	PVOID elements;
	DWORD unk2;
	DWORD unk3;
} STRUCT_MINESWEEPER_REF_ELEMENT, *PSTRUCT_MINESWEEPER_REF_ELEMENT;

typedef struct _STRUCT_MINESWEEPER_BOARD {
	PVOID Serializer;
	DWORD cbMines;
	DWORD cbRows;
	DWORD cbColumns;
	DWORD unk0;
	DWORD unk1;
	DWORD unk2;
	DWORD unk3;
	DWORD unk4;
	DWORD unk5;
	DWORD unk6;
	DWORD unk7;
	DWORD unk8;
	DWORD unk9;
	PVOID unk10;
	PVOID unk11;
	PSTRUCT_MINESWEEPER_REF_ELEMENT	ref_visibles;
	PSTRUCT_MINESWEEPER_REF_ELEMENT	ref_mines;
	DWORD unk12;
	DWORD unk13;
} STRUCT_MINESWEEPER_BOARD, *PSTRUCT_MINESWEEPER_BOARD;

typedef struct _STRUCT_MINESWEEPER_GAME {
	PVOID Serializer;
	//PVOID pGameStat; on 7x86
	PVOID pNodeBase;
	PVOID pBoardCanvas;
	PSTRUCT_MINESWEEPER_BOARD pBoard;
	PSTRUCT_MINESWEEPER_BOARD pBoard_WIN7x86;
} STRUCT_MINESWEEPER_GAME, *PSTRUCT_MINESWEEPER_GAME;

void kuhl_m_minesweeper_infos_parseField(PKULL_M_MEMORY_HANDLE hMemory, PSTRUCT_MINESWEEPER_REF_ELEMENT base, CHAR ** field, BOOL isVisible);
//
//void __fastcall kuhl_m_minesweeper_bsod_thread(PVOID a, INT b, INT c, BOOL d);
//DWORD kuhl_m_minesweeper_bsod_thread_end();