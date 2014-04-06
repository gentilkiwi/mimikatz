/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globals.h"
#include <io.h>
#include <fcntl.h>

FILE * logfile;

void kprintf(PCWCHAR format, ...);
void kprintf_inputline(PCWCHAR format, ...);

BOOL kull_m_output_file(PCWCHAR file);