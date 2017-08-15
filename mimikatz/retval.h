#pragma once
#include <globals.h>
#include <Windows.h>
#define WINDOWS_MAX_USERNAME_PASS_LENGTH (257)

typedef struct Node Node;
typedef struct List List;
typedef struct LogonData LogonData;


struct Node
{
	LogonData* data;
	Node* next;
};

struct LogonData
{
	WCHAR username[WINDOWS_MAX_USERNAME_PASS_LENGTH];
	WCHAR password[WINDOWS_MAX_USERNAME_PASS_LENGTH];
	BYTE lmHash[LM_NTLM_HASH_LENGTH];
	BYTE ntlmHash[LM_NTLM_HASH_LENGTH];
};

struct List
{
	size_t length;
	Node* first;
	Node* last;
};

List* s_list;


Node* Node_create(LogonData* item);
void Node_delete(Node* node);

List* List_create();
void List_delete(List* list);
void List_addItem(List* list, LogonData* item);
LogonData List_pop(List* list);
size_t List_getLength(List* list);

LogonData* LogonData_create(WCHAR* username, size_t username_size, WCHAR* password, size_t password_size, BYTE* lmHash, BYTE* ntlmHash);
void LogonData_delete(LogonData* logonData);
LogonData LogonData_generateEmpty();
