#ifndef SYSTEM_PROCESS_INFO_H
#define SYSTEM_PROCESS_INFO_H

unsigned int GetProcessInfo(__out char** ProcessInfo, __in unsigned int Length);

VOID WriteProcessModulesInfo(HANDLE hProcess, DWORD dwPID, CMarkup *xml);

VOID GetApplicationVersion(LPTSTR szFullPath, LPTSTR szVersion);

void GetInfoFromExeAndDll(LPTSTR szFileFullPath, LPTSTR szCompanyName);

VOID GetProcessUserName(HANDLE hProcess, LPTSTR szUserName);

int GetProcessIsWOW64(HANDLE hProcess);

VOID EnableDebugPrivilege();

#endif
