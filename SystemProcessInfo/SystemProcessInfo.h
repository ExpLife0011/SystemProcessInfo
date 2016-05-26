#ifndef __SYSTEM_PROCESS_INFO_H__
#define __SYSTEM_PROCESS_INFO_H__

// 导出接口
unsigned int GetProcessInfo(__out char** ProcessInfo, __in unsigned int Length);

// 获取进程模块详细信息
DWORD WriteProcessModulesInfo(HANDLE hProcess, DWORD dwPID, CMarkup *xml);

// 获取文件的版本信息
DWORD GetApplicationVersion(LPTSTR szFullPath, LPTSTR szVersion);

// 获取EXE或DLL的厂商信息
DWORD GetInfoFromExeAndDll(LPTSTR szFileFullPath, LPTSTR szCompanyName);

// 获取进程所属用户
DWORD GetProcessUserName(HANDLE hProcess, LPTSTR szUserName);

// 判断进程是32位还是64位
int GetProcessIsWOW64(HANDLE hProcess);

// 提升为 Debug 权限
BOOL EnableDebugPrivilege(BOOL bEnable);

#endif
