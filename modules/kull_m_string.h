/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"

typedef struct _KIWI_DATETIME_FORMATS {
	LPCWSTR format;
	int minFields;
	BYTE idxYear;
	BYTE idxMonth;
	BYTE idxDay;
	BYTE idxHour;
	BYTE idxMinute;
	BYTE idxSecond;
} KIWI_DATETIME_FORMATS, *PKIWI_DATETIME_FORMATS;

typedef CONST char *PCSZ;
typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;
typedef PSTRING PCANSI_STRING;

typedef STRING OEM_STRING;
typedef PSTRING POEM_STRING;
typedef CONST STRING* PCOEM_STRING;
typedef CONST UNICODE_STRING *PCUNICODE_STRING;

#define DECLARE_UNICODE_STRING(_var, _string) \
const WCHAR _var ## _buffer[] = _string; \
UNICODE_STRING _var = { sizeof(_string) - sizeof(WCHAR), sizeof(_string), (PWCH) _var ## _buffer }

#define DECLARE_CONST_UNICODE_STRING(_var, _string) \
const WCHAR _var ## _buffer[] = _string; \
const UNICODE_STRING _var = { sizeof(_string) - sizeof(WCHAR), sizeof(_string), (PWCH) _var ## _buffer }

extern VOID WINAPI RtlInitString(OUT PSTRING DestinationString, IN PCSZ SourceString);
extern VOID WINAPI RtlInitUnicodeString(OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString);

extern NTSTATUS WINAPI RtlAnsiStringToUnicodeString(OUT PUNICODE_STRING DestinationString, IN PCANSI_STRING SourceString, IN BOOLEAN AllocateDestinationString);
extern NTSTATUS WINAPI RtlUnicodeStringToAnsiString(OUT PANSI_STRING DestinationString, IN PCUNICODE_STRING SourceString, IN BOOLEAN AllocateDestinationString);

extern VOID WINAPI RtlUpperString(OUT PSTRING DestinationString, IN const STRING *SourceString);
extern NTSTATUS WINAPI RtlUpcaseUnicodeString(IN OUT PUNICODE_STRING DestinationString, IN PCUNICODE_STRING SourceString, IN BOOLEAN AllocateDestinationString);
extern NTSTATUS WINAPI RtlDowncaseUnicodeString(PUNICODE_STRING DestinationString, IN PCUNICODE_STRING SourceString, IN BOOLEAN AllocateDestinationString);
extern WCHAR WINAPI RtlUpcaseUnicodeChar(IN WCHAR SourceCharacter);
extern NTSTATUS WINAPI RtlUpcaseUnicodeStringToOemString(IN OUT POEM_STRING DestinationString, IN PCUNICODE_STRING SourceString, IN BOOLEAN AllocateDestinationString);

extern BOOLEAN WINAPI RtlEqualString(IN const STRING *String1, IN const STRING *String2, IN BOOLEAN CaseInSensitive);
extern BOOLEAN WINAPI RtlEqualUnicodeString(IN PCUNICODE_STRING String1, IN PCUNICODE_STRING String2, IN BOOLEAN CaseInSensitive);

extern LONG WINAPI RtlCompareUnicodeString(IN PCUNICODE_STRING String1, IN PCUNICODE_STRING String2, IN BOOLEAN CaseInSensitive);
extern LONG WINAPI RtlCompareString(IN const STRING *String1, IN const STRING *String2, IN BOOLEAN CaseInSensitive);

extern VOID WINAPI RtlFreeAnsiString(IN OUT PANSI_STRING AnsiString);
extern VOID WINAPI RtlFreeUnicodeString(IN OUT PUNICODE_STRING UnicodeString);
extern VOID WINAPI RtlFreeOemString(IN OUT POEM_STRING OemString);

extern NTSTATUS WINAPI RtlStringFromGUID(IN LPCGUID Guid, PUNICODE_STRING UnicodeString);
extern NTSTATUS WINAPI RtlGUIDFromString(IN PCUNICODE_STRING GuidString, OUT GUID *Guid);
extern NTSTATUS NTAPI RtlValidateUnicodeString(IN ULONG Flags, IN PCUNICODE_STRING UnicodeString);

extern NTSTATUS WINAPI RtlAppendUnicodeStringToString(IN OUT PUNICODE_STRING Destination, IN PCUNICODE_STRING Source);

extern VOID NTAPI RtlRunDecodeUnicodeString(IN BYTE Hash, IN OUT PUNICODE_STRING String);
extern VOID NTAPI RtlRunEncodeUnicodeString(IN OUT PBYTE Hash, IN OUT PUNICODE_STRING String);

//BOOL kull_m_string_suspectUnicodeStringStructure(IN PUNICODE_STRING pUnicodeString);
void kull_m_string_MakeRelativeOrAbsoluteString(PVOID BaseAddress, PLSA_UNICODE_STRING String, BOOL relative);
BOOL kull_m_string_copyUnicodeStringBuffer(PUNICODE_STRING pSource, PUNICODE_STRING pDestination);
void kull_m_string_freeUnicodeStringBuffer(PUNICODE_STRING pString);
BOOL kull_m_string_suspectUnicodeString(IN PUNICODE_STRING pUnicodeString);
void kull_m_string_printSuspectUnicodeString(PVOID data, DWORD size);

wchar_t * kull_m_string_qad_ansi_to_unicode(const char * ansi);
wchar_t * kull_m_string_qad_ansi_c_to_unicode(const char * ansi, SIZE_T szStr);
char * kull_m_string_unicode_to_ansi(const wchar_t * unicode);
BOOL kull_m_string_stringToHex(IN LPCWCHAR string, IN LPBYTE hex, IN DWORD size);
BOOL kull_m_string_stringToHexBuffer(IN LPCWCHAR string, IN LPBYTE *hex, IN DWORD *size);

void kull_m_string_wprintf_hex(LPCVOID lpData, DWORD cbData, DWORD flags);
void kull_m_string_displayFileTime(IN PFILETIME pFileTime);
void kull_m_string_displayLocalFileTime(IN PFILETIME pFileTime);
BOOL kull_m_string_FileTimeToString(IN PFILETIME pFileTime, OUT WCHAR string[14 + 1]);
void kull_m_string_displayGUID(IN LPCGUID pGuid);
void kull_m_string_displaySID(IN PSID pSid);
PWSTR kull_m_string_getRandomGUID();
void kull_m_string_ptr_replace(PVOID ptr, DWORD64 size);

BOOL kull_m_string_args_byName(const int argc, const wchar_t * argv[], const wchar_t * name, const wchar_t ** theArgs, const wchar_t * defaultValue);
BOOL kull_m_string_args_bool_byName(int argc, wchar_t * argv[], LPCWSTR name, PBOOL value);
BOOL kull_m_string_copy_len(LPWSTR *dst, LPCWSTR src, size_t size);
BOOL kull_m_string_copy(LPWSTR *dst, LPCWSTR src);
BOOL kull_m_string_copyA_len(LPSTR *dst, LPCSTR src, size_t size);
BOOL kull_m_string_copyA(LPSTR *dst, LPCSTR src);
BOOL kull_m_string_quickxml_simplefind(LPCWSTR xml, LPCWSTR node, LPWSTR *dst);
#if !defined(MIMIKATZ_W2000_SUPPORT)
BOOL kull_m_string_quick_base64_to_Binary(PCWSTR base64, PBYTE *data, DWORD *szData);
#endif
BOOL kull_m_string_sprintf(PWSTR *outBuffer, PCWSTR format, ...);
BOOL kull_m_string_stringToFileTime(LPCWSTR string, PFILETIME filetime);