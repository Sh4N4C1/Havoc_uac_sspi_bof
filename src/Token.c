#include <windows.h>
#include <security.h>

#define TOKEN_OWNER_FLAG_DEFAULT 0x0 /* query domain/user */
#define TOKEN_OWNER_FLAG_USER 0x1 /* query user only */
#define TOKEN_OWNER_FLAG_DOMAIN 0x2 /* query domain only */

#define B_PTR( x )      ( ( PBYTE ) ( x ) )
#define NtCurrentProcess()  ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)
#define PRINT_WINAPI_ERROR(szWnApiName) BeaconPrintf(CALLBACK_OUTPUT, "[!] %s Failed With Error: %d \n", szWnApiName, KERNEL32$GetLastError());


#define SEC_SUCCESS(Status) ((Status) >= 0)
#define MAX_MESSAGE_SIZE 12000

typedef struct _PBUFFER{
    PVOID   Buffer;
    UINT32  Length;
}BUFFER, *PBUFFER;

typedef struct _PPRIVSLIST{
    PCHAR   Name;
    DWORD   Flags;
}PRIVSLIST, *PPRIVSLIST;

typedef struct _PGROUPLIST{
    PCHAR   Name;
    PCHAR   Sid;
    PCHAR   Domain;
}GROUPLIST, *PGROUPLIST;

HANDLE TokenCurrentHandle(VOID){

    HANDLE hToken = NULL;
    ADVAPI32$OpenThreadToken(NtCurrentThread(), TOKEN_QUERY, TRUE, &hToken);

    if(hToken == NULL)
        ADVAPI32$OpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &hToken);

    return hToken;
}
BOOL TokenQueryOwner(IN HANDLE hToken, OUT PBUFFER UserDomain, IN DWORD Flags){

    PTOKEN_USER UserInfo = NULL;
    ULONG UserSize = 0;
    PVOID Domain = NULL;
    PVOID User = NULL;
    DWORD UserLen = {0};
    DWORD DomnLen = {0};
    SID_NAME_USE SidType = {0};

    if (!hToken || !UserDomain)
        return FALSE;

    /* Get Size of the TOKEN_USER structure */
    if(!ADVAPI32$GetTokenInformation(hToken, TokenUser, UserInfo, 0, &UserSize) && UserSize == 0x00)
    {
        PRINT_WINAPI_ERROR("GetTokenInformation");
        return FALSE;
    }

    /* Malloc memory via UserSize */
    UserInfo = (PTOKEN_USER)MSVCRT$malloc(UserSize);

    /* Query The Token User (SID) */
    if(!ADVAPI32$GetTokenInformation(hToken, TokenUser, UserInfo, UserSize, &UserSize))
    {
        PRINT_WINAPI_ERROR("GetTokenInformation");
        return FALSE;
    }

    if(!ADVAPI32$LookupAccountSidW(NULL, UserInfo->User.Sid, NULL, &UserLen, NULL, &DomnLen, &SidType) && UserLen == 0x00 && DomnLen == 0x00)
    {
        PRINT_WINAPI_ERROR("LookupAccountSidW");
        return FALSE;
    }

    SidType = 0;

    if(Flags == TOKEN_OWNER_FLAG_USER)
        UserDomain->Length = (UserLen * sizeof(WCHAR));
    else if (Flags == TOKEN_OWNER_FLAG_DOMAIN)
        UserDomain->Length = (DomnLen * sizeof(WCHAR));
    else 
        UserDomain->Length = (UserLen * sizeof(WCHAR)) + (DomnLen * sizeof(WCHAR));

    UserDomain->Buffer = (PWCHAR)MSVCRT$malloc(UserDomain->Length);
    Domain = UserDomain->Buffer;
    User = (UserDomain->Buffer + (DomnLen * sizeof(WCHAR)));

    if(Flags == TOKEN_OWNER_FLAG_USER)
    {
        Domain = MSVCRT$malloc(DomnLen * sizeof(WCHAR));
        User = UserDomain->Buffer;
    }else if (Flags == TOKEN_OWNER_FLAG_DOMAIN)
    {
        User = MSVCRT$malloc(UserLen * sizeof(WCHAR));
    }
    
    if (!ADVAPI32$LookupAccountSidW(NULL, UserInfo->User.Sid, User, &UserLen, Domain, &DomnLen, &SidType))
    {
        PRINT_WINAPI_ERROR("LookupAccountSidW");
        return FALSE;
    }

    if (Flags == TOKEN_OWNER_FLAG_DEFAULT)
        B_PTR(UserDomain->Buffer)[(DomnLen * sizeof(WCHAR))] = '\\';

    return TRUE;

}

BOOL TokenQueryPrivs(IN HANDLE hToken, OUT PPRIVSLIST* PrivsList, OUT DWORD* PrivsCount){
    
    PTOKEN_PRIVILEGES pPrivs = NULL;
    DWORD PrivsLen = 0x00;
    DWORD Length = 0x00;

    if (!hToken)
        return FALSE;

    if(!ADVAPI32$GetTokenInformation(hToken, TokenPrivileges, pPrivs, 0, &PrivsLen) && PrivsLen == 0x00)
    {
        PRINT_WINAPI_ERROR("GetTokenInformation");
        return FALSE;
    }
    pPrivs = (PTOKEN_PRIVILEGES)MSVCRT$malloc(PrivsLen);

    if(!ADVAPI32$GetTokenInformation(hToken, TokenPrivileges, pPrivs, PrivsLen, &PrivsLen) 
            && PrivsLen == 0x00)
    {
        PRINT_WINAPI_ERROR("GetTokenInformation");
        return FALSE;
    }

    CHAR Name[MAX_PATH] = {0};
    *PrivsList = (PPRIVSLIST)MSVCRT$malloc((pPrivs->PrivilegeCount) * sizeof(PRIVSLIST));

    for(int i = 0; i < pPrivs->PrivilegeCount; i++){
        Length = MAX_PATH;
        ADVAPI32$LookupPrivilegeNameA(NULL, &pPrivs->Privileges[i].Luid, Name, &Length);
        (*PrivsList)[i].Name = MSVCRT$malloc(MSVCRT$strlen(Name) + 1 );
        MSVCRT$strcpy((*PrivsList)[i].Name, Name);
        (*PrivsList)[i].Flags = pPrivs->Privileges[i].Attributes;
    }

    *PrivsCount = pPrivs->PrivilegeCount;

    return TRUE;


}


HANDLE ForgeNetworkAuthToken()
{

    CredHandle hCredClient, hCredServer;
    TimeStamp lifetimeClient, lifetimeServer;
    SecBufferDesc negotiateDesc, challengeDesc, authenticateDesc;
    SecBuffer negotiateBuffer, challengeBuffer, authenticateBuffer;
    CtxtHandle clientContextHandle, serverContextHandle;
    ULONG clientContextAttributes, serverContextAttributes;
    SECURITY_STATUS secStatus;
    SEC_CHAR* NTLMSP_NAME2 = "NTLM";
    HANDLE hTokenNetwork = 0x00;

    secStatus = SECUR32$AcquireCredentialsHandleA(NULL, NTLMSP_NAME2, SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, &hCredClient,
                                         &lifetimeClient);
    if (!SEC_SUCCESS(secStatus))
    {
        PRINT_WINAPI_ERROR("AcquireCredentialsHandleA");
        return NULL;
    }

    secStatus = SECUR32$AcquireCredentialsHandleA(NULL, NTLMSP_NAME2, SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &hCredServer,
                                         &lifetimeServer);
    if (!SEC_SUCCESS(secStatus))
    {
        PRINT_WINAPI_ERROR("AcquireCredentialsHandleA");
        return NULL;
    }

    negotiateDesc.ulVersion = 0;
    negotiateDesc.cBuffers = 1;
    negotiateDesc.pBuffers = &negotiateBuffer;

    negotiateBuffer.cbBuffer = MAX_MESSAGE_SIZE;
    negotiateBuffer.BufferType = SECBUFFER_TOKEN;
    negotiateBuffer.pvBuffer = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_MESSAGE_SIZE);

    /* the client call InitializeSecurityContext */
    /* the server call AcceptSecurityContext */
    /* frist the client will set initialize pack */
    secStatus =
        SECUR32$InitializeSecurityContextA(&hCredClient, NULL, NULL, ISC_REQ_DATAGRAM, 0, SECURITY_NATIVE_DREP, NULL, 0,
                                  &clientContextHandle, &negotiateDesc, &clientContextAttributes, &lifetimeClient);

    if (!SEC_SUCCESS(secStatus))
    {
        PRINT_WINAPI_ERROR("InitializeSecurityContextA");
        return NULL;
    }


    /* then we set challenge data message pack */
    challengeDesc.ulVersion = 0;
    challengeDesc.cBuffers = 1;
    challengeDesc.pBuffers = &challengeBuffer;
    challengeBuffer.cbBuffer = MAX_MESSAGE_SIZE;
    challengeBuffer.BufferType = SECBUFFER_TOKEN;
    challengeBuffer.pvBuffer = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_MESSAGE_SIZE);
    secStatus = SECUR32$AcceptSecurityContext(&hCredServer, NULL, &negotiateDesc, ASC_REQ_DATAGRAM, SECURITY_NATIVE_DREP,
                                      &serverContextHandle, &challengeDesc, &serverContextAttributes, &lifetimeServer);

    if (!SEC_SUCCESS(secStatus))
    {
        PRINT_WINAPI_ERROR("AcceptSecurityContext");
        return NULL;
    }

    /* after send challenge message, we need call InitializeSecurityContext on Client */

	authenticateDesc.ulVersion = 0;
	authenticateDesc.cBuffers = 1;
	authenticateDesc.pBuffers = &authenticateBuffer;
	authenticateBuffer.cbBuffer = MAX_MESSAGE_SIZE;
	authenticateBuffer.BufferType = SECBUFFER_TOKEN;
	authenticateBuffer.pvBuffer = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_MESSAGE_SIZE);
    secStatus =
        SECUR32$InitializeSecurityContextA(NULL, &clientContextHandle, NULL, 0, 0, SECURITY_NATIVE_DREP, &challengeDesc, 0,
                                  &clientContextHandle, &authenticateDesc, &clientContextAttributes, &lifetimeClient);
    if (!SEC_SUCCESS(secStatus))
    {
        PRINT_WINAPI_ERROR("InitializeSecurityContextA");
        return NULL;
    }

    /* the server AcceptSecurityContext after client send authentication message */

    secStatus = SECUR32$AcceptSecurityContext(NULL, &serverContextHandle, &authenticateDesc, 0, SECURITY_NATIVE_DREP,
                                      &serverContextHandle, NULL, &serverContextAttributes, &lifetimeServer);
    if (!SEC_SUCCESS(secStatus))
    {
        PRINT_WINAPI_ERROR("AcceptSecurityContext");
        return NULL;
    }

    /* clean up */
    SECUR32$QuerySecurityContextToken(&serverContextHandle, &hTokenNetwork);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, negotiateBuffer.pvBuffer);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, challengeBuffer.pvBuffer);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, authenticateBuffer.pvBuffer);
    SECUR32$FreeCredentialsHandle(&hCredClient);
    SECUR32$FreeCredentialsHandle(&hCredServer);
    SECUR32$DeleteSecurityContext(&clientContextHandle);
    SECUR32$DeleteSecurityContext(&serverContextHandle);

    return hTokenNetwork;
}
