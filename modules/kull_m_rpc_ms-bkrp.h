#pragma once
#include "kull_m_rpc.h"

const GUID BACKUPKEY_BACKUP_GUID, BACKUPKEY_RESTORE_GUID_WIN2K, BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID, BACKUPKEY_RESTORE_GUID;

NET_API_STATUS BackuprKey(handle_t h, GUID *pguidActionAgent, byte *pDataIn, DWORD cbDataIn, byte **ppDataOut, DWORD *pcbDataOut, DWORD dwParam);