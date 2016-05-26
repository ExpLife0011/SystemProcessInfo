#ifndef __SYSTEM_PROCESS_INFO_H__
#define __SYSTEM_PROCESS_INFO_H__

// �����ӿ�
unsigned int GetProcessInfo(__out char** ProcessInfo, __in unsigned int Length);

// ��ȡ����ģ����ϸ��Ϣ
DWORD WriteProcessModulesInfo(HANDLE hProcess, DWORD dwPID, CMarkup *xml);

// ��ȡ�ļ��İ汾��Ϣ
DWORD GetApplicationVersion(LPTSTR szFullPath, LPTSTR szVersion);

// ��ȡEXE��DLL�ĳ�����Ϣ
DWORD GetInfoFromExeAndDll(LPTSTR szFileFullPath, LPTSTR szCompanyName);

// ��ȡ���������û�
DWORD GetProcessUserName(HANDLE hProcess, LPTSTR szUserName);

// �жϽ�����32λ����64λ
int GetProcessIsWOW64(HANDLE hProcess);

// ����Ϊ Debug Ȩ��
BOOL EnableDebugPrivilege(BOOL bEnable);

#endif
