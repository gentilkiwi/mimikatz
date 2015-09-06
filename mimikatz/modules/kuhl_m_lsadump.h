/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "kerberos/kuhl_m_kerberos.h"
#include "../modules/kull_m_process.h"
#include "../modules/kull_m_service.h"
#include "../modules/kull_m_memory.h"
#include "../modules/kull_m_patch.h"
#include "../modules/kull_m_registry.h"
#include "../modules/kull_m_crypto_system.h"
#include "../modules/kull_m_string.h"
#include "../modules/kull_m_samlib.h"
#include "../modules/kull_m_net.h"
#include "../modules/kull_m_rpc_drsr.h"
#include "kuhl_m_lsadump_remote.h"
#include "kuhl_m_crypto.h"
#include "dpapi/kuhl_m_dpapi_oe.h"

#define	SYSKEY_LENGTH	16
#define	SAM_KEY_DATA_SALT_LENGTH	16
#define	SAM_KEY_DATA_KEY_LENGTH		16

typedef struct _SAM_ENTRY {
	DWORD offset;
	DWORD lenght;
	DWORD unk;
} SAM_ENTRY, *PSAM_SENTRY;

typedef struct _KIWI_BACKUP_KEY {
	DWORD version;
	DWORD keyLen;
	DWORD certLen;
	BYTE data[ANYSIZE_ARRAY];
} KIWI_BACKUP_KEY, *PKIWI_BACKUP_KEY;

typedef struct _NTDS_LSA_AUTH_INFORMATION {
    LARGE_INTEGER LastUpdateTime;
    ULONG AuthType;
    ULONG AuthInfoLength;
	UCHAR AuthInfo[ANYSIZE_ARRAY]; //
} NTDS_LSA_AUTH_INFORMATION, *PNTDS_LSA_AUTH_INFORMATION;

typedef struct _NTDS_LSA_AUTH_INFORMATIONS {
	DWORD count; // or version ?
	DWORD offsetToAuthenticationInformation;	// PLSA_AUTH_INFORMATION
	DWORD offsetToPreviousAuthenticationInformation;	// PLSA_AUTH_INFORMATION
	// ...
} NTDS_LSA_AUTH_INFORMATIONS, *PNTDS_LSA_AUTH_INFORMATIONS;

#pragma pack(push, 1) 
typedef struct _USER_PROPERTY {
	USHORT NameLength;
	USHORT ValueLength;
	USHORT Reserved;
	wchar_t PropertyName[ANYSIZE_ARRAY];
	// PropertyValue in HEX !
} USER_PROPERTY, *PUSER_PROPERTY;

typedef struct _USER_PROPERTIES {
	DWORD Reserved1;
	DWORD Length;
	USHORT Reserved2;
	USHORT Reserved3;
	BYTE Reserved4[96];
	wchar_t PropertySignature;
	USHORT PropertyCount;
	USER_PROPERTY UserProperties[ANYSIZE_ARRAY];
} USER_PROPERTIES, *PUSER_PROPERTIES;
#pragma pack(pop)

const KUHL_M kuhl_m_lsadump;

NTSTATUS kuhl_m_lsadump_init();

NTSTATUS kuhl_m_lsadump_sam(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_lsa(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_secrets(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_cache(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_trust(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_secretsOrCache(int argc, wchar_t * argv[], BOOL secretsOrCache);
NTSTATUS kuhl_m_lsadump_bkey(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_rpdata(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_dcsync(int argc, wchar_t * argv[]);

BOOL kuhl_m_lsadump_getSids(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hPolicyBase, IN LPCWSTR littleKey, IN LPCWSTR prefix);
BOOL kuhl_m_lsadump_getComputerAndSyskey(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hSystemBase, OUT LPBYTE sysKey);
BOOL kuhl_m_lsadump_getUsersAndSamKey(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hSAMBase, IN LPBYTE sysKey);

BOOL kuhl_m_lsadump_getCurrentControlSet(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hSystemBase, PHKEY phCurrentControlSet);
BOOL kuhl_m_lsadump_getSyskey(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hLSA, LPBYTE sysKey);
BOOL kuhl_m_lsadump_getSamKey(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hAccount, LPCBYTE sysKey, LPBYTE samKey);
BOOL kuhl_m_lsadump_getHash(PSAM_SENTRY pSamHash, LPCBYTE pStartOfData, LPCBYTE samKey, DWORD rid, BOOL isNtlm);

void kuhl_m_lsadump_lsa_user(SAMPR_HANDLE DomainHandle, DWORD rid, PUNICODE_STRING name, PKULL_M_MEMORY_ADDRESS aRemoteThread);
BOOL kuhl_m_lsadump_lsa_getHandle(PKULL_M_MEMORY_HANDLE * hMemory, DWORD Flags);
void kuhl_m_lsadump_trust_authinformation(PLSA_AUTH_INFORMATION info, DWORD count, PNTDS_LSA_AUTH_INFORMATION infoNtds, PCWSTR prefix, PCUNICODE_STRING from, PCUNICODE_STRING dest);

NTSTATUS kuhl_m_lsadump_LsaRetrievePrivateData(PCWSTR systemName, PCWSTR secretName, PUNICODE_STRING secret, BOOL isInject);
void kuhl_m_lsadump_analyzeKey(LPCGUID guid, PKIWI_BACKUP_KEY secret, DWORD size, BOOL isExport);
NTSTATUS kuhl_m_lsadump_getKeyFromGUID(LPCGUID guid, BOOL isExport, LPCWSTR systemName, BOOL isInject);

typedef  enum _DOMAIN_SERVER_ROLE
{
	DomainServerRoleBackup = 2,
	DomainServerRolePrimary = 3
} DOMAIN_SERVER_ROLE, *PDOMAIN_SERVER_ROLE;

typedef  enum _DOMAIN_SERVER_ENABLE_STATE
{
	DomainServerEnabled = 1,
	DomainServerDisabled
} DOMAIN_SERVER_ENABLE_STATE, *PDOMAIN_SERVER_ENABLE_STATE;

typedef struct _OLD_LARGE_INTEGER {
	ULONG LowPart;
	LONG HighPart;
} OLD_LARGE_INTEGER, *POLD_LARGE_INTEGER;

typedef struct _SAM_KEY_DATA {
	DWORD Revision;
	DWORD Length;
	BYTE Salt[SAM_KEY_DATA_SALT_LENGTH];
	BYTE Key[SAM_KEY_DATA_KEY_LENGTH];
	BYTE CheckSum[MD5_DIGEST_LENGTH];
	DWORD unk0;
	DWORD unk1;
} SAM_KEY_DATA, *PSAM_KEY_DATA;

typedef struct _DOMAIN_ACCOUNT_F {
	DWORD Revision;
	DWORD unk1;
	OLD_LARGE_INTEGER CreationTime;
	OLD_LARGE_INTEGER DomainModifiedCount;
	OLD_LARGE_INTEGER MaxPasswordAge;
	OLD_LARGE_INTEGER MinPasswordAge;
	OLD_LARGE_INTEGER ForceLogoff;
	OLD_LARGE_INTEGER LockoutDuration;
	OLD_LARGE_INTEGER LockoutObservationWindow;
	OLD_LARGE_INTEGER ModifiedCountAtLastPromotion;
	DWORD NextRid;
	DWORD PasswordProperties;
	WORD MinPasswordLength;
	WORD PasswordHistoryLength;
	WORD LockoutThreshold;
	DOMAIN_SERVER_ENABLE_STATE ServerState;
	DOMAIN_SERVER_ROLE ServerRole;
	BOOL UasCompatibilityRequired;
	DWORD unk2;
	SAM_KEY_DATA keys1;
	SAM_KEY_DATA keys2;
	DWORD unk3;
	DWORD unk4;
} DOMAIN_ACCOUNT_F, *PDOMAIN_ACCOUNT_F;

typedef struct _USER_ACCOUNT_V {
	SAM_ENTRY unk0_header;
	SAM_ENTRY Username;
	SAM_ENTRY Fullname;
	SAM_ENTRY Comment;
	SAM_ENTRY UserComment;
	SAM_ENTRY unk1;
	SAM_ENTRY Homedir;
	SAM_ENTRY HomedirConnect;
	SAM_ENTRY ScriptPath;
	SAM_ENTRY ProfilePath;
	SAM_ENTRY Workstations;
	SAM_ENTRY HoursAllowed;
	SAM_ENTRY unk2;
	SAM_ENTRY LMHash;
	SAM_ENTRY NTLMHash;
	SAM_ENTRY unk3;
	SAM_ENTRY unk4;
	BYTE datas[ANYSIZE_ARRAY];
} USER_ACCOUNT_V, *PUSER_ACCOUNT_V;

typedef struct _SAM_HASH {
	DWORD flag;
	BYTE hash[LM_NTLM_HASH_LENGTH];
} SAM_HASH, *PSAM_HASH;

typedef struct _POL_REVISION {
	USHORT Minor;
	USHORT Major;
} POL_REVISION, *PPOL_REVISION;

typedef struct _NT6_CLEAR_SECRET {
	DWORD SecretSize;
	DWORD unk0;
	DWORD unk1;
	DWORD unk2;
	BYTE  Secret[ANYSIZE_ARRAY];
} NT6_CLEAR_SECRET, *PNT6_CLEAR_SECRET;

#define LAZY_NT6_IV_SIZE	32
typedef struct _NT6_HARD_SECRET {
	DWORD version;
	GUID KeyId;
	DWORD algorithm;
	DWORD flag;
	BYTE lazyiv[LAZY_NT6_IV_SIZE];
	union {
		NT6_CLEAR_SECRET clearSecret;
		BYTE encryptedSecret[ANYSIZE_ARRAY];
	};
} NT6_HARD_SECRET, *PNT6_HARD_SECRET;

typedef struct _NT6_SYSTEM_KEY {
	GUID KeyId;
	DWORD KeyType;
	DWORD KeySize;
	BYTE Key[ANYSIZE_ARRAY];
} NT6_SYSTEM_KEY, *PNT6_SYSTEM_KEY;

typedef struct _NT6_SYSTEM_KEYS {
	DWORD unkType0;
	GUID CurrentKeyID;
	DWORD unkType1;
	DWORD nbKeys;
	NT6_SYSTEM_KEY Keys[ANYSIZE_ARRAY];
} NT6_SYSTEM_KEYS, *PNT6_SYSTEM_KEYS;

typedef struct _NT5_HARD_SECRET {
	DWORD encryptedStructSize;
	DWORD unk0;
	DWORD unk1; // it's a trap, it's PTR !
	BYTE encryptedSecret[ANYSIZE_ARRAY];
} NT5_HARD_SECRET, *PNT5_HARD_SECRET;

typedef struct _NT5_SYSTEM_KEY {
	BYTE key[16];
} NT5_SYSTEM_KEY, *PNT5_SYSTEM_KEY;

#define LAZY_IV_SIZE	16
typedef struct _NT5_SYSTEM_KEYS {
	DWORD unk0;
	DWORD unk1;
	DWORD unk2;
	NT5_SYSTEM_KEY keys[3];
	BYTE lazyiv[LAZY_IV_SIZE];
} NT5_SYSTEM_KEYS, *PNT5_SYSTEM_KEYS;

typedef struct _MSCACHE_ENTRY {
	WORD szUserName;
	WORD szDomainName;
	WORD szEffectiveName;
	WORD szfullName;
	WORD szlogonScript;
	WORD szprofilePath;
	WORD szhomeDirectory;
	WORD szhomeDirectoryDrive;
	DWORD userId;
	DWORD primaryGroupId;
	DWORD groupCount;
	WORD szlogonDomainName;
	WORD unk0;
	FILETIME lastWrite;
	DWORD revision;
	DWORD sidCount;
	DWORD flags;
	DWORD unk1;
	DWORD logonPackage;
	WORD szDnsDomainName;
	WORD szupn;
	BYTE iv[LAZY_IV_SIZE];
	BYTE cksum[MD5_DIGEST_LENGTH];
	BYTE enc_data[ANYSIZE_ARRAY];
} MSCACHE_ENTRY, *PMSCACHE_ENTRY;

typedef struct _MSCACHE_DATA {
	BYTE mshashdata[LM_NTLM_HASH_LENGTH];
	BYTE unkhash[LM_NTLM_HASH_LENGTH];
	DWORD unk0;
	DWORD unk1;
	DWORD unkLength;
	DWORD unk2;
	DWORD unk3;
	DWORD unk4;
	DWORD unk5;
	DWORD unk6;
	DWORD unk7;
	DWORD unk8;
} MSCACHE_DATA, *PMSCACHE_DATA;

typedef struct _WDIGEST_CREDENTIALS {
	BYTE	Reserverd1;
	BYTE	Reserverd2;
	BYTE	Version;
	BYTE	NumberOfHashes;
	BYTE	Reserverd3[12];
	BYTE	Hash[ANYSIZE_ARRAY][MD5_DIGEST_LENGTH];
} WDIGEST_CREDENTIALS, *PWDIGEST_CREDENTIALS;

typedef struct _KERB_KEY_DATA {
	USHORT	Reserverd1;
	USHORT	Reserverd2;
	ULONG	Reserverd3;
	LONG	KeyType;
	ULONG	KeyLength;
	ULONG	KeyOffset;
} KERB_KEY_DATA, *PKERB_KEY_DATA;

typedef struct _KERB_STORED_CREDENTIAL {
	USHORT	Revision;
	USHORT	Flags;
	USHORT	CredentialCount;
	USHORT	OldCredentialCount;
	USHORT	DefaultSaltLength;
	USHORT	DefaultSaltMaximumLength;
	ULONG	DefaultSaltOffset;
	//KERB_KEY_DATA	Credentials[ANYSIZE_ARRAY];
	//KERB_KEY_DATA	OldCredentials[ANYSIZE_ARRAY];
	//BYTE	DefaultSalt[ANYSIZE_ARRAY];
	//BYTE	KeyValues[ANYSIZE_ARRAY];
} KERB_STORED_CREDENTIAL, *PKERB_STORED_CREDENTIAL;

typedef struct _KERB_KEY_DATA_NEW {
	USHORT	Reserverd1;
	USHORT	Reserverd2;
	ULONG	Reserverd3;
	ULONG	IterationCount;
	LONG	KeyType;
	ULONG	KeyLength;
	ULONG	KeyOffset;
} KERB_KEY_DATA_NEW, *PKERB_KEY_DATA_NEW;

typedef struct _KERB_STORED_CREDENTIAL_NEW {
	USHORT	Revision;
	USHORT	Flags;
	USHORT	CredentialCount;
	USHORT	ServiceCredentialCount;
	USHORT	OldCredentialCount;
	USHORT	OlderCredentialCount;
	USHORT	DefaultSaltLength;
	USHORT	DefaultSaltMaximumLength;
	ULONG	DefaultSaltOffset;
	ULONG	DefaultIterationCount;
	//KERB_KEY_DATA_NEW	Credentials[ANYSIZE_ARRAY];
	//KERB_KEY_DATA_NEW	ServiceCredentials[ANYSIZE_ARRAY];
	//KERB_KEY_DATA_NEW	OldCredentials[ANYSIZE_ARRAY];
	//KERB_KEY_DATA_NEW	OlderCredentials[ANYSIZE_ARRAY];
	//BYTE	DefaultSalt[ANYSIZE_ARRAY];
	//BYTE	KeyValues[ANYSIZE_ARRAY];
} KERB_STORED_CREDENTIAL_NEW, *PKERB_STORED_CREDENTIAL_NEW;

typedef struct _LSA_SUPCREDENTIAL {
	DWORD	type;
	DWORD	size;
	DWORD	offset;
	DWORD	Reserved;
} LSA_SUPCREDENTIAL, *PLSA_SUPCREDENTIAL;

typedef struct _LSA_SUPCREDENTIALS {
	DWORD	count;
	DWORD	Reserved;
} LSA_SUPCREDENTIALS, *PLSA_SUPCREDENTIALS;

typedef struct _LSA_SUPCREDENTIALS_BUFFERS {
	LSA_SUPCREDENTIAL credential;
	NTSTATUS status;
	PVOID Buffer;
} LSA_SUPCREDENTIALS_BUFFERS, *PLSA_SUPCREDENTIALS_BUFFERS;

BOOL kuhl_m_lsadump_getLsaKeyAndSecrets(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hSecurityBase, IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, IN LPBYTE sysKey, IN BOOL secretsOrCache, IN BOOL kiwime);
BOOL kuhl_m_lsadump_getSecrets(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hPolicyBase, IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, PNT6_SYSTEM_KEYS lsaKeysStream, PNT5_SYSTEM_KEY lsaKeyUnique);
BOOL kuhl_m_lsadump_getNLKMSecretAndCache(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hPolicyBase, IN HKEY hSecurityBase, PNT6_SYSTEM_KEYS lsaKeysStream, PNT5_SYSTEM_KEY lsaKeyUnique, BOOL kiwime);
void kuhl_m_lsadump_printMsCache(PMSCACHE_ENTRY entry, CHAR version);
void kuhl_m_lsadump_getInfosFromServiceName(IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, IN PCWSTR serviceName);
BOOL kuhl_m_lsadump_decryptSecret(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hSecret, IN PNT6_SYSTEM_KEYS lsaKeysStream, IN PNT5_SYSTEM_KEY lsaKeyUnique, IN PVOID * pBufferOut, IN PDWORD pSzBufferOut);
void kuhl_m_lsadump_candidateSecret(DWORD szBytesSecrets, PVOID bufferSecret, PCWSTR prefix, PCWSTR secretName);
BOOL kuhl_m_lsadump_sec_aes256(PNT6_HARD_SECRET hardSecretBlob, DWORD hardSecretBlobSize, PNT6_SYSTEM_KEYS lsaKeysStream, PBYTE sysKey);

PKERB_KEY_DATA kuhl_m_lsadump_lsa_keyDataInfo(PVOID base, PKERB_KEY_DATA keys, USHORT Count, PCWSTR title);
PKERB_KEY_DATA_NEW kuhl_m_lsadump_lsa_keyDataNewInfo(PVOID base, PKERB_KEY_DATA_NEW keys, USHORT Count, PCWSTR title);
void kuhl_m_lsadump_lsa_DescrBuffer(DWORD type, PVOID Buffer, DWORD BufferSize);

PVOID kuhl_m_lsadump_dcsync_findMonoAttr(ATTRBLOCK *attributes, ATTRTYP type, PVOID data, DWORD *size);
void kuhl_m_lsadump_dcsync_findPrintMonoAttr(LPCWSTR prefix, ATTRBLOCK *attributes, ATTRTYP type, BOOL newLine);

BOOL kuhl_m_lsadump_dcsync_decrypt(PBYTE encodedData, DWORD encodedDataSize, DWORD rid, LPCWSTR prefix, BOOL isHistory);
void kuhl_m_lsadump_dcsync_descrObject(ATTRBLOCK *attributes, LPCWSTR szSrcDomain);
void kuhl_m_lsadump_dcsync_descrUser(ATTRBLOCK *attributes);
void kuhl_m_lsadump_dcsync_descrUserProperties(PUSER_PROPERTIES properties);
void kuhl_m_lsadump_dcsync_descrTrust(ATTRBLOCK *attributes, LPCWSTR szSrcDomain);
void kuhl_m_lsadump_dcsync_descrTrustAuthentication(ATTRBLOCK *attributes, ATTRTYP type, PCUNICODE_STRING domain, PCUNICODE_STRING partner);