/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include <io.h>
#include <fcntl.h>
#include <wincrypt.h>

BOOL isBase64Output;
FILE * logfile;
#if !defined(MIMIKATZ_W2000_SUPPORT)
wchar_t * outputBuffer;
size_t outputBufferElements, outputBufferElementsPosition;
#endif

void kprintf(PCWCHAR format, ...);
void kprintf_inputline(PCWCHAR format, ...);

BOOL kull_m_output_file(PCWCHAR file);

void kull_m_output_init();
void kull_m_output_clean();
