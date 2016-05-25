#include "StdAfx.h"
#include "SystemProcessInfo.h"

unsigned int GetProcessInfo(__out char** ProcessInfo, __in unsigned int Length)
{
	CMarkup xml;
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32; 

	xml.SetDoc(_T("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"));
	xml.AddElem(_T("CATALOG"));
	xml.AddAttrib(_T("value"), _T("进程信息"));
	xml.IntoElem();

	// Snapshot
	hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if( hProcessSnap != INVALID_HANDLE_VALUE )
	{
		pe32.dwSize = sizeof( PROCESSENTRY32 );

		// Enum process
		if( Process32First( hProcessSnap, &pe32 ) )
		{
			do
			{
				if (lstrcmp(pe32.szExeFile, _T("[System Process]")) == 0 ||
					lstrcmp(pe32.szExeFile, _T("System")) == 0)
				{
					continue;
				}
				xml.AddElem(_T("PROCESS"));
				xml.IntoElem();

				// Process Name
				xml.AddElem(_T("PROCESSNAME"), pe32.szExeFile);

				// Process Id
				xml.AddElem(_T("PROCESSID"), pe32.th32ProcessID);

				// Process session Id
				DWORD dwSessionId = 0;
				ProcessIdToSessionId(pe32.th32ProcessID, &dwSessionId);
				xml.AddElem(_T("PROCESSSESSIONID"), dwSessionId);
				
				hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID );
				if( hProcess != NULL )
				{
					// Process bit
					0 == GetProcessIsWOW64(hProcess) ? 
						xml.AddElem(_T("PROCESSBIT"), _T("64")) :
						xml.AddElem(_T("PROCESSBIT"), _T("32"));

					// Process as user
					TCHAR szProcessAsUser[MAX_PATH] = _T("0");
					GetProcessUserName(hProcess, szProcessAsUser);
					xml.AddElem(_T("PROCESSASUSER"), szProcessAsUser);

					// Process Path
					TCHAR szFilePath[MAX_PATH] = { 0 };
					GetModuleFileNameEx(hProcess, NULL, szFilePath, MAX_PATH);
					xml.AddElem(_T("PROCESSPATH"), szFilePath);

					// Process file version
					TCHAR szFileVersion[MAX_PATH] = _T("0");
					GetApplicationVersion(szFilePath, szFileVersion);
					xml.AddElem(_T("PROCESSVERSION"), szFileVersion);

					// Memory info
					PROCESS_MEMORY_COUNTERS pmc = { 0 };
					GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc));
					xml.AddElem(_T("USEMEMORY"), (int)pmc.WorkingSetSize / 1024);

					// Process thread count
					xml.AddElem(_T("THREADCOUNT"), pe32.cntThreads);

					// Modules info
					WriteProcessModulesInfo(hProcess, pe32.th32ProcessID, &xml);
					// Close handle
					CloseHandle(hProcess);
				}

				xml.OutOfElem();
			} while( Process32Next( hProcessSnap, &pe32 ) );
		}

		xml.OutOfElem();
		CloseHandle( hProcessSnap );
	}

	int len = WideCharToMultiByte(CP_ACP, 0, xml.GetDoc(), 
		xml.GetDoc().GetLength(), NULL, 0, NULL, NULL);

	// If buffer is NULL, return buffer size.
	if (NULL == *ProcessInfo)
	{
		return len;
	}

	WideCharToMultiByte(CP_ACP, 0, xml.GetDoc(), 
		xml.GetDoc().GetLength(), *ProcessInfo, len, NULL, NULL);

	xml.Save(_T("SystemProcessInfo.xml"));

	return 0;
}

VOID GetApplicationVersion(LPTSTR szFullPath, LPTSTR szVersion)
{
	DWORD dwVerInfoSize = 0;
	DWORD dwVerHnd;
	VS_FIXEDFILEINFO * pFileInfo;

	dwVerInfoSize = GetFileVersionInfoSize(szFullPath, &dwVerHnd);
	if (dwVerInfoSize)
	{
		// If we were able to get the information, process it:
		HANDLE  hMem;
		LPVOID  lpvMem;
		unsigned int uInfoSize = 0;

		hMem = GlobalAlloc(GMEM_MOVEABLE, dwVerInfoSize);
		lpvMem = GlobalLock(hMem);
		GetFileVersionInfo(szFullPath, dwVerHnd, dwVerInfoSize, lpvMem);

		::VerQueryValue(lpvMem, (LPTSTR)_T("\\"), (void**)&pFileInfo, &uInfoSize);

		WORD m_nProdVersion[4];
		// Product version from the FILEVERSION of the version info resource 
		m_nProdVersion[0] = HIWORD(pFileInfo->dwProductVersionMS); 
		m_nProdVersion[1] = LOWORD(pFileInfo->dwProductVersionMS);
		m_nProdVersion[2] = HIWORD(pFileInfo->dwProductVersionLS);
		m_nProdVersion[3] = LOWORD(pFileInfo->dwProductVersionLS); 

		wsprintf(szVersion, _T("%d.%d.%d.%d"),m_nProdVersion[0],
			m_nProdVersion[1],m_nProdVersion[2],m_nProdVersion[3]);

		GlobalUnlock(hMem);
		GlobalFree(hMem);
	}
}

void GetInfoFromExeAndDll(LPTSTR szFileFullPath, LPTSTR szCompanyName)
{
    struct LANGANDCODEPAGE
    {
        WORD wLanguage;
        WORD wCodePage;
    };
    DWORD dwSize = 0;
    UINT uiSize = GetFileVersionInfoSize(szFileFullPath, &dwSize);
    if (0 == uiSize)
    {
        return;
    }
    PTSTR pBuffer = new TCHAR[uiSize];
    if (NULL == pBuffer)
    {
        return;
    }
    memset((void*)pBuffer, 0, uiSize);
    
    if (!GetFileVersionInfo(szFileFullPath, 0, uiSize, (PVOID)pBuffer))
    {
        return;
    }
    LANGANDCODEPAGE *pLanguage = NULL;
    UINT  uiOtherSize = 0;
    
    if (!VerQueryValue(pBuffer, _T("\\VarFileInfo\\Translation"),(PVOID*)&pLanguage, &uiOtherSize))
    {
        return;
    }

    char* pTmp = NULL;   
    TCHAR SubBlock[MAX_PATH];
    memset((void*)SubBlock, 0, sizeof(SubBlock));
    UINT uLen = 0;

    int ret = uiOtherSize / sizeof(LANGANDCODEPAGE);
    if (ret > 0)
    {
        wsprintf(SubBlock, TEXT("\\StringFileInfo\\%04x%04x\\CompanyName"), 
			pLanguage[0].wLanguage, pLanguage[0].wCodePage);

        if(VerQueryValue(pBuffer, SubBlock, (PVOID*)&pTmp, &uLen))
			memcpy(szCompanyName, pTmp, uLen * sizeof(TCHAR));
    }
    delete[]pBuffer;
    pBuffer = NULL;
}

VOID GetProcessUserName(HANDLE hProcess, LPTSTR szUserName)
{
	HANDLE hToken = NULL;
	BOOL bFuncReturn = FALSE;
	PTOKEN_USER pToken_User = NULL;
	DWORD dwTokenUser = 0;
	TCHAR szAccName[MAX_PATH] = {0};
	TCHAR szDomainName[MAX_PATH] = {0};
	HANDLE hProcessToken = NULL;

	if(hProcess != NULL)
	{
		bFuncReturn = ::OpenProcessToken(hProcess,TOKEN_QUERY,&hToken);

		if( bFuncReturn == 0)
		{
			return;
		}

		if(hToken != NULL)
		{
			::GetTokenInformation(hToken, TokenUser, NULL, 0L, &dwTokenUser);

			if(dwTokenUser>0)
			{
				pToken_User = (PTOKEN_USER)::GlobalAlloc( GPTR, dwTokenUser );
			}

			if(pToken_User != NULL)
			{
				bFuncReturn = ::GetTokenInformation(hToken, TokenUser, pToken_User, dwTokenUser, &dwTokenUser);
			}

			if(bFuncReturn != FALSE && pToken_User != NULL)
			{
				SID_NAME_USE eUse  = SidTypeUnknown;

				DWORD dwAccName    = 0L; 
				DWORD dwDomainName = 0L;

				PSID  pSid = pToken_User->User.Sid;

				bFuncReturn = ::LookupAccountSid(NULL, pSid, NULL, &dwAccName,
					NULL,&dwDomainName,&eUse );
				if(dwAccName>0 && dwAccName < MAX_PATH && dwDomainName>0 && dwDomainName <= MAX_PATH)
				{
					bFuncReturn = ::LookupAccountSid(NULL,pSid,szAccName,&dwAccName,
						szDomainName,&dwDomainName,&eUse );
				}

				if( bFuncReturn != 0)
					memcpy(szUserName, szAccName, sizeof(szAccName));
			}
		}
	}

	if (pToken_User != NULL)
	{
		::GlobalFree( pToken_User );
	}

	if(hToken != NULL)
	{
		::CloseHandle(hToken);
	}
}

int GetProcessIsWOW64(HANDLE hProcess)
{
	int nRet=-1;

	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL); 
	LPFN_ISWOW64PROCESS fnIsWow64Process; 
	BOOL bIsWow64 = FALSE; 
	BOOL bRet;
	DWORD nError;
	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress( GetModuleHandle(L"kernel32"),"IsWow64Process"); 
	if (NULL != fnIsWow64Process) 
	{ 
		bRet = fnIsWow64Process(hProcess,&bIsWow64);
		if (bRet==0)
		{
			nError=GetLastError();
			nRet=-2;
		}
		else
		{
			if (bIsWow64)
			{
				nRet=1;
			}
			else
			{
				nRet=0;
			}
		}
	} 
	return nRet; 
}

VOID WriteProcessModulesInfo(HANDLE hProcess, DWORD dwPID, CMarkup *xml)
{
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;
	// Snapshot

	hModuleSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwPID );

	if( hModuleSnap != INVALID_HANDLE_VALUE )
	{
		xml->AddElem(_T("MODULELIST"));
		xml->IntoElem();
		
		me32.dwSize = sizeof( MODULEENTRY32 );
		if( Module32First( hModuleSnap, &me32 ) )
		{
			do
			{
				TCHAR szCompanyName[MAX_PATH] = { 0 };
				GetInfoFromExeAndDll(me32.szExePath, szCompanyName);
				if (lstrcmp(szCompanyName, _T("Microsoft Corporation")) != 0 ||
					lstrlen(szCompanyName) == 0)
				{
					xml->AddElem(_T("MODULE"));
					xml->IntoElem();

					// Module name
					xml->AddElem(_T("MODULECOMPANYNAME"), szCompanyName);

					// Module name
					xml->AddElem(_T("MODULENAME"), me32.szModule);

					// Module version
					TCHAR szModuleVersion[MAX_PATH] = _T("0");
					GetApplicationVersion(me32.szExePath, szModuleVersion);
					xml->AddElem(_T("MODULEVERSION"), szModuleVersion);

					// Module path
					xml->AddElem(_T("MODULEPATH"), me32.szExePath);

					xml->OutOfElem();
				}

			} while( Module32Next( hModuleSnap, &me32 ) );
		}

		xml->OutOfElem();
		CloseHandle( hModuleSnap );
	}
	
	return ;
}

VOID EnableDebugPrivilege()
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue);

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 

	AdjustTokenPrivileges(hToken, false, &tkp, sizeof tkp, NULL, NULL);
	CloseHandle(hToken);
}