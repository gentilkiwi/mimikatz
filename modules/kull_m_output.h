/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include <io.h>
#include <fcntl.h>

FILE * logfile;
//#ifdef _WINDLL
wchar_t * outputBuffer;
size_t outputBufferElements, outputBufferElementsPosition;
//#endif

void kprintf(PCWCHAR format, ...);

BOOL kull_m_output_file(PCWCHAR file);

void kull_m_output_init();
void kull_m_output_clean();