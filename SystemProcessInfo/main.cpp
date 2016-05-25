// SystemProcessInfo.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "SystemProcessInfo.h"


int _tmain(int argc, _TCHAR* argv[])
{
	EnableDebugPrivilege();

	char *buffer = NULL;
	unsigned int nResult = 0;

	nResult = GetProcessInfo(NULL, 0);

	if (nResult != 0)
	{
		buffer = (char*)malloc(nResult + 1);
		memset(buffer, 0, nResult + 1);
		GetProcessInfo(&buffer, nResult);
	}

	printf("%s", buffer);

	system("PAUSE");
	return 0;
}

