/*
 * scmcheck.c — Service Control Manager Permission Check BOF
 * ----------------------------------------------------------
 * Standalone check for dangerous SCM-level permissions.
 * Splits the SCM check out of modsvc so it can be run independently.
 */

#include <windows.h>
#include <winsvc.h>
#include "beacon.h"

/* ==================== Import Declarations ==================== */

DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetCurrentProcess(VOID);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT HLOCAL  WINAPI KERNEL32$LocalAlloc(UINT, SIZE_T);
DECLSPEC_IMPORT HLOCAL  WINAPI KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);

DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$EqualSid(PSID, PSID);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$GetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR, LPBOOL, PACL*, LPBOOL);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$GetAclInformation(PACL, LPVOID, DWORD, ACL_INFORMATION_CLASS);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$GetAce(PACL, DWORD, LPVOID*);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR, LPCSTR, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$QueryServiceObjectSecurity(SC_HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, DWORD, LPDWORD);

/* SC_MANAGER_CREATE_SERVICE, SC_MANAGER_MODIFY_BOOT_CONFIG, and
   SC_MANAGER_ALL_ACCESS are provided by winsvc.h — no redefinition needed */

/* ==================== Structs ==================== */

typedef struct _ACCESS_CHECK_RESULT {
    BOOL HasAccess;
    BOOL IsAllowed;
    BOOL IsDenied;
    char IdentityName[256];
} ACCESS_CHECK_RESULT;

/* ==================== Global Output Buffer ==================== */

static formatp g_fmt;

static void InitOutput(void) {
    BeaconFormatAlloc(&g_fmt, 32768);
}

static void FlushOutput(void) {
    int size = 0;
    char* data = BeaconFormatToString(&g_fmt, &size);
    BeaconOutput(CALLBACK_OUTPUT, data, size);
    BeaconFormatFree(&g_fmt);
}

/* ==================== Helpers ==================== */

static BOOL IsSidInTokenGroups(PSID pTargetSid) {
    HANDLE hToken         = NULL;
    PTOKEN_GROUPS pGroups = NULL;
    DWORD dwSize          = 0;
    BOOL bResult          = FALSE;

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
                                   TOKEN_QUERY, &hToken))
        return FALSE;

    ADVAPI32$GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwSize);
    if (KERNEL32$GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }

    pGroups = (PTOKEN_GROUPS)KERNEL32$LocalAlloc(LPTR, dwSize);
    if (!pGroups)
        goto cleanup;

    if (!ADVAPI32$GetTokenInformation(hToken, TokenGroups,
                                      pGroups, dwSize, &dwSize))
        goto cleanup;

    for (DWORD i = 0; i < pGroups->GroupCount; i++) {
        if (ADVAPI32$EqualSid(pTargetSid, pGroups->Groups[i].Sid)) {
            bResult = TRUE;
            break;
        }
    }

cleanup:
    if (pGroups) KERNEL32$LocalFree(pGroups);
    if (hToken)  KERNEL32$CloseHandle(hToken);
    return bResult;
}

static void LookupSidName(PSID pSid, char* buf, DWORD bufLen) {
    char domainName[256];
    DWORD nameLen   = bufLen;
    DWORD domainLen = sizeof(domainName);
    SID_NAME_USE use;
    buf[0] = '\0';
    ADVAPI32$LookupAccountSidA(NULL, pSid, buf, &nameLen,
                                domainName, &domainLen, &use);
}

static ACCESS_CHECK_RESULT CheckAccessAgainstDacl(
        PSECURITY_DESCRIPTOR pSD, DWORD dwDesiredAccess) {

    ACCESS_CHECK_RESULT result   = {0};
    PACL  pDacl                  = NULL;
    BOOL  bDaclPresent           = FALSE;
    BOOL  bDaclDefaulted         = FALSE;
    PTOKEN_USER pTokenUser       = NULL;
    HANDLE hToken                = NULL;
    DWORD dwSize                 = 0;

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
                                   TOKEN_QUERY, &hToken))
        return result;

    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    if (KERNEL32$GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        goto cleanup;

    pTokenUser = (PTOKEN_USER)KERNEL32$LocalAlloc(LPTR, dwSize);
    if (!pTokenUser)
        goto cleanup;

    if (!ADVAPI32$GetTokenInformation(hToken, TokenUser,
                                      pTokenUser, dwSize, &dwSize))
        goto cleanup;

    if (!ADVAPI32$GetSecurityDescriptorDacl(pSD, &bDaclPresent,
                                            &pDacl, &bDaclDefaulted))
        goto cleanup;

    if (!bDaclPresent || !pDacl) {
        result.HasAccess = TRUE;
        result.IsAllowed = TRUE;
        goto cleanup;
    }

    ACL_SIZE_INFORMATION aclInfo = {0};
    if (!ADVAPI32$GetAclInformation(pDacl, &aclInfo,
                                    sizeof(aclInfo), AclSizeInformation))
        goto cleanup;

    /* Pass 1: deny ACEs */
    for (DWORD i = 0; i < aclInfo.AceCount; i++) {
        LPVOID pAce = NULL;
        if (!ADVAPI32$GetAce(pDacl, i, &pAce)) continue;

        ACE_HEADER*  pHdr    = (ACE_HEADER*)pAce;
        PSID         pAceSid = NULL;
        ACCESS_MASK  aceMask = 0;

        if (pHdr->AceType == ACCESS_DENIED_ACE_TYPE) {
            ACCESS_DENIED_ACE* p = (ACCESS_DENIED_ACE*)pAce;
            pAceSid = (PSID)&p->SidStart; aceMask = p->Mask;
        } else if (pHdr->AceType == ACCESS_DENIED_CALLBACK_ACE_TYPE) {
            ACCESS_DENIED_CALLBACK_ACE* p = (ACCESS_DENIED_CALLBACK_ACE*)pAce;
            pAceSid = (PSID)&p->SidStart; aceMask = p->Mask;
        } else { continue; }

        if ((ADVAPI32$EqualSid(pAceSid, pTokenUser->User.Sid) ||
             IsSidInTokenGroups(pAceSid)) &&
            (aceMask & dwDesiredAccess)) {
            result.IsDenied = TRUE;
            LookupSidName(pAceSid, result.IdentityName,
                          sizeof(result.IdentityName));
            goto cleanup;
        }
    }

    /* Pass 2: allow ACEs */
    for (DWORD i = 0; i < aclInfo.AceCount; i++) {
        LPVOID pAce = NULL;
        if (!ADVAPI32$GetAce(pDacl, i, &pAce)) continue;

        ACE_HEADER*  pHdr    = (ACE_HEADER*)pAce;
        PSID         pAceSid = NULL;
        ACCESS_MASK  aceMask = 0;

        if (pHdr->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            ACCESS_ALLOWED_ACE* p = (ACCESS_ALLOWED_ACE*)pAce;
            pAceSid = (PSID)&p->SidStart; aceMask = p->Mask;
        } else if (pHdr->AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE) {
            ACCESS_ALLOWED_CALLBACK_ACE* p = (ACCESS_ALLOWED_CALLBACK_ACE*)pAce;
            pAceSid = (PSID)&p->SidStart; aceMask = p->Mask;
        } else { continue; }

        if ((ADVAPI32$EqualSid(pAceSid, pTokenUser->User.Sid) ||
             IsSidInTokenGroups(pAceSid)) &&
            (aceMask & dwDesiredAccess)) {
            result.HasAccess = TRUE;
            result.IsAllowed = TRUE;
            LookupSidName(pAceSid, result.IdentityName,
                          sizeof(result.IdentityName));
            goto cleanup;
        }
    }

cleanup:
    if (pTokenUser) KERNEL32$LocalFree(pTokenUser);
    if (hToken)     KERNEL32$CloseHandle(hToken);
    return result;
}

/* ==================== SCM Permission Check ==================== */

static void CheckSCMPermissions(void) {
    BeaconFormatPrintf(&g_fmt,
        "\n=== Service Control Manager Permissions ===\n\n");

    SC_HANDLE hScm = ADVAPI32$OpenSCManagerA(
        NULL, SERVICES_ACTIVE_DATABASE,
        SC_MANAGER_CONNECT | READ_CONTROL);

    if (!hScm) {
        BeaconFormatPrintf(&g_fmt,
            "[-] OpenSCManager failed: %d\n",
            KERNEL32$GetLastError());
        return;
    }

    DWORD dwSize = 0;
    ADVAPI32$QueryServiceObjectSecurity(
        hScm, DACL_SECURITY_INFORMATION, NULL, 0, &dwSize);

    if (KERNEL32$GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        BeaconFormatPrintf(&g_fmt,
            "[-] QueryServiceObjectSecurity (size) failed: %d\n",
            KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(hScm);
        return;
    }

    PSECURITY_DESCRIPTOR pSD =
        (PSECURITY_DESCRIPTOR)KERNEL32$LocalAlloc(LPTR, dwSize);
    if (!pSD) {
        ADVAPI32$CloseServiceHandle(hScm);
        return;
    }

    if (!ADVAPI32$QueryServiceObjectSecurity(
            hScm, DACL_SECURITY_INFORMATION, pSD, dwSize, &dwSize)) {
        BeaconFormatPrintf(&g_fmt,
            "[-] QueryServiceObjectSecurity failed: %d\n",
            KERNEL32$GetLastError());
        KERNEL32$LocalFree(pSD);
        ADVAPI32$CloseServiceHandle(hScm);
        return;
    }

    DWORD       rights[]     = { SC_MANAGER_CREATE_SERVICE,
                                  SC_MANAGER_MODIFY_BOOT_CONFIG,
                                  SC_MANAGER_ALL_ACCESS };
    const char* rightNames[] = { "CreateService",
                                  "ModifyBootConfig",
                                  "AllAccess" };

    BOOL foundAny = FALSE;
    for (int i = 0; i < 3; i++) {
        ACCESS_CHECK_RESULT r =
            CheckAccessAgainstDacl(pSD, rights[i]);
        if (r.IsAllowed && !r.IsDenied) {
            BeaconFormatPrintf(&g_fmt,
                "[!] SCM: current user has %s\n"
                "    Identity : %s\n\n",
                rightNames[i],
                r.IdentityName[0] ? r.IdentityName : "(unknown)");
            foundAny = TRUE;
        }
    }

    if (!foundAny)
        BeaconFormatPrintf(&g_fmt,
            "[+] No dangerous SCM permissions found.\n");

    KERNEL32$LocalFree(pSD);
    ADVAPI32$CloseServiceHandle(hScm);
}

/* ==================== Entry Point ==================== */

void go(char* args, int len) {
    InitOutput();
    BeaconFormatPrintf(&g_fmt,
        "\n[*] scmcheck BOF — SCM Permission Check\n"
        "[*] ----------------------------------------\n");

    CheckSCMPermissions();

    FlushOutput();
}
