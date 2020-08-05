// Most code here is based on Stephen Fewer's Reflective DLL Injection Code
//===============================================================================================//
// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#include "stdafx.h"
#include "LoadLibraryR.h"
#include "byte_mod.h"
#include "ReflectiveLoader.h"
#include "houdini.h"
//===============================================================================================//

LPVOID last_shared_mem_addr = NULL;
DWORD shared_mem_size = 0;

LPVOID MapSharedMemory(HANDLE sharedMemHandle);
DWORD GetDllInMemorySize(ULONG_PTR baseAddress);


DWORD Rva2Offset( DWORD dwRva, UINT_PTR uiBaseAddress )
{    
	WORD wIndex                          = 0;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders         = NULL;
	
	pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

    if( dwRva < pSectionHeader[0].PointerToRawData )
        return dwRva;

    for( wIndex=0 ; wIndex < pNtHeaders->FileHeader.NumberOfSections ; wIndex++ )
    {   
        if( dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData) )           
           return ( dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData );
    }
    
    return 0;
}
//===============================================================================================//
DWORD GetExportedSymbolOffset( VOID * lpReflectiveDllBuffer, char* searchString )
{
	UINT_PTR uiBaseAddress   = 0;
	UINT_PTR uiExportDir     = 0;
	UINT_PTR uiNameArray     = 0;
	UINT_PTR uiAddressArray  = 0;
	UINT_PTR uiNameOrdinals  = 0;
	DWORD dwCounter          = 0;
#ifdef WIN_X64
	DWORD dwCompiledArch = 2;
#else
	// This will catch Win32 and WinRT.
	DWORD dwCompiledArch = 1;
#endif

#ifdef _DEBUG
	printf("Start searching symbol '%s' in library with base: %p\n", searchString, lpReflectiveDllBuffer);
#endif
	uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

	// get the File Offset of the modules NT Header
	uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

	// currenlty we can only process a PE file which is the same type as the one this fuction has  
	// been compiled as, due to various offset in the PE structures being defined at compile time.
	if( ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x010B ) // PE32
	{
		if( dwCompiledArch != 1 )
			return 0;
	}
	else if( ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x020B ) // PE64
	{
		if( dwCompiledArch != 2 )
			return 0;
	}
	else
	{
		return 0;
	}

	// uiNameArray = the address of the modules export directory entry
	uiNameArray = (UINT_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

	// get the File Offset of the export directory
	uiExportDir = uiBaseAddress + Rva2Offset( ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress );

	// get the File Offset for the array of name pointers
	uiNameArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNames, uiBaseAddress );

	// get the File Offset for the array of addresses
	uiAddressArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, uiBaseAddress );

	// get the File Offset for the array of name ordinals
	uiNameOrdinals = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNameOrdinals, uiBaseAddress );	

	// get a counter for the number of exported functions...
	dwCounter = ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->NumberOfNames;

	// loop through all the exported functions to find the ReflectiveLoader
	while( dwCounter-- )
	{
		char * cpExportedFunctionName = (char *)(uiBaseAddress + Rva2Offset( DEREF_32( uiNameArray ), uiBaseAddress ));

		//if( strstr( cpExportedFunctionName, "ReflectiveLoader" ) != NULL )
		if (strstr(cpExportedFunctionName, searchString) != NULL)
		{
			// get the File Offset for the array of addresses
			uiAddressArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, uiBaseAddress );	
	
			// use the functions name ordinal as an index into the array of name pointers
			uiAddressArray += ( DEREF_16( uiNameOrdinals ) * sizeof(DWORD) );

			// return the File Offset to the ReflectiveLoader() functions code...
			return Rva2Offset( DEREF_32( uiAddressArray ), uiBaseAddress );
		}
		// get the next exported function name
		uiNameArray += sizeof(DWORD);

		// get the next exported function name ordinal
		uiNameOrdinals += sizeof(WORD);
	}

	return 0;
}


// TODO integrate
// Taken from ReflectiveLoader.c
BOOL PerformRelocations(ULONG_PTR uiBaseAddress, ULONG_PTR lastAddress){
	ULONG_PTR uiValueA;
	ULONG_PTR uiValueB;
	ULONG_PTR uiValueC;
	ULONG_PTR uiValueD;
	LONG64 imageOffset;

	ULONG_PTR uiHeaderValue = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

	imageOffset = uiBaseAddress - lastAddress;

	// uiValueB = the address of the relocation directory
	uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (((PIMAGE_DATA_DIRECTORY)uiValueB)->Size)
	{
		// uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
		uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

		// and we itterate through all entries...
		while (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock)
		{
			// uiValueA = the VA for this relocation block
			uiValueA = (uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress);

			// uiValueB = number of entries in this relocation block
			uiValueB = (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

			// uiValueD is now the first entry in the current relocation block
			uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

			// we itterate through all the entries in the current block...
			while (uiValueB--)
			{
				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// we dont use a switch statement to avoid the compiler building a jump table
				// which would not be very position independent!
				if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64)
					*(ULONG_PTR *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += imageOffset;
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW)
					*(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)imageOffset;
#ifdef WIN_ARM
				// Note: On ARM, the compiler optimization /O2 seems to introduce an off by one issue, possibly a code gen bug. Using /O1 instead avoids this problem.
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_ARM_MOV32T)
				{
					register DWORD dwInstruction;
					register DWORD dwAddress;
					register WORD wImm;
					// get the MOV.T instructions DWORD value (We add 4 to the offset to go past the first MOV.W which handles the low word)
					dwInstruction = *(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset + sizeof(DWORD));
					// flip the words to get the instruction as expected
					dwInstruction = MAKELONG(HIWORD(dwInstruction), LOWORD(dwInstruction));
					// sanity chack we are processing a MOV instruction...
					if ((dwInstruction & ARM_MOV_MASK) == ARM_MOVT)
					{
						// pull out the encoded 16bit value (the high portion of the address-to-relocate)
						wImm = (WORD)(dwInstruction & 0x000000FF);
						wImm |= (WORD)((dwInstruction & 0x00007000) >> 4);
						wImm |= (WORD)((dwInstruction & 0x04000000) >> 15);
						wImm |= (WORD)((dwInstruction & 0x000F0000) >> 4);
						// apply the relocation to the target address
						dwAddress = ((WORD)HIWORD(imageOffset) + wImm) & 0xFFFF;
						// now create a new instruction with the same opcode and register param.
						dwInstruction = (DWORD)(dwInstruction & ARM_MOV_MASK2);
						// patch in the relocated address...
						dwInstruction |= (DWORD)(dwAddress & 0x00FF);
						dwInstruction |= (DWORD)(dwAddress & 0x0700) << 4;
						dwInstruction |= (DWORD)(dwAddress & 0x0800) << 15;
						dwInstruction |= (DWORD)(dwAddress & 0xF000) << 4;
						// now flip the instructions words and patch back into the code...
						*(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset + sizeof(DWORD)) = MAKELONG(HIWORD(dwInstruction), LOWORD(dwInstruction));
					}
				}
#endif
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH)
					*(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += HIWORD(imageOffset);
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW)
					*(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += LOWORD(imageOffset);

				// get the next entry in the current relocation block
				uiValueD += sizeof(IMAGE_RELOC);
			}

			// get the next entry in the relocation directory
			uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
		}
	}
	return TRUE;
}


//===============================================================================================//
// Starts the ReflectiveLoader function in the memory mapped DLL and retrieves its base address
// and shared memory handle
ULONG_PTR LoadLibraryRS( LPVOID lpBuffer, DWORD dwLength, char* secretKey )
{
	DWORD dwReflectiveLoaderOffset = 0;
	DWORD dwOldProtect1 = 0;
	DWORD dwOldProtect2                = 0;
	REFLECTIVELOADER pReflectiveLoader = NULL;
	DLLMAIN pDllMain                   = NULL;
	HANDLE sharedMemHandle			   = NULL;
	ULONG_PTR dllEntryPoint = NULL;

	if( lpBuffer == NULL || dwLength == 0 )
		return NULL;

	__try
	{

		if (secretKey != NULL){
			endecrypt_inplace((char *)lpBuffer, dwLength, secretKey);
#ifdef _DEBUG
			printf("First bytes of decrypted buffer: %s\n", lpBuffer);
#endif
		}
		// check if the library has a ReflectiveLoader...
		dwReflectiveLoaderOffset = GetExportedSymbolOffset( lpBuffer, "ReflectiveLoader" );
		if( dwReflectiveLoaderOffset != 0 )
		{
			pReflectiveLoader = (REFLECTIVELOADER)((UINT_PTR)lpBuffer + dwReflectiveLoaderOffset);
#ifdef _DEBUG
			printf("Reflective loader is at: %p\n", pReflectiveLoader);
#endif
			// we must VirtualProtect the buffer to RWX so we can execute the ReflectiveLoader...
			// this assumes lpBuffer is the base address of the region of pages and dwLength the size of the region
			if( VirtualProtect( lpBuffer, dwLength, PAGE_EXECUTE_READWRITE, &dwOldProtect1 ) )
			{
				// call the librarys ReflectiveLoader...
				dllEntryPoint = pReflectiveLoader();
				pDllMain = (DLLMAIN)(dllEntryPoint);
				if (pDllMain != NULL){

#ifdef _DEBUG
					printf("DLLMain function address: %p\n", pDllMain);
					printf("Calling entry point to get base address and shared memory handle...\n");
#endif

					HMODULE hResult = NULL;
					if (!pDllMain(NULL, DLL_QUERY_HMODULE, &hResult))
						hResult = NULL;
					else{
						last_shared_mem_addr = (LPVOID)hResult;
						shared_mem_size = GetDllInMemorySize((ULONG_PTR)last_shared_mem_addr);
					}
				}
				// revert to the previous protection flags...
				VirtualProtect( lpBuffer, dwLength, dwOldProtect1, &dwOldProtect2 );
			}
		}
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		dllEntryPoint = NULL;
#ifdef _DEBUG
		printf("Exception occured in LoadLibraryRS\n");
#endif
	}

	return dllEntryPoint;
}

//===============================================================================================//
// Loads a previously setup DLL with its shared memory handle by mapping it, calling entrypoint
// and unmapping it again
BOOL WINAPI MapAndExecuteLibrary(HANDLE sharedMemHandle, LONG64 entryPointOffset)
{

	DLLMAIN pDllMain = NULL;
	LPVOID sharedMemPointer = NULL;
	BOOL result = FALSE;

	__try
	{
		sharedMemPointer = MapSharedMemory(sharedMemHandle);
		if (!sharedMemPointer){
#ifdef _DEBUG
			printf("Mapping shared memory failed.\n", sharedMemPointer);
#endif
			return FALSE;
		}
#ifdef _DEBUG
		printf("Shared memory is currently mapped here: %p\n", sharedMemPointer);
		printf("First bytes of shared memory: %s\n", sharedMemPointer);
#endif

		ULONG_PTR dllEntryPoint = ((ULONG_PTR)sharedMemPointer + entryPointOffset);
#ifdef _DEBUG
		printf("DLL Entrypoint: %p\n", dllEntryPoint);
#endif
		if (dllEntryPoint > 0){
			// TODO make shared memory relocatable
			//ULONG_PTR temp_last_addr = last_shared_mem_addr;
			//if (temp_last_addr == NULL){
			//	ULONG_PTR uiHeaderValue = (ULONG_PTR)sharedMemPointer + ((PIMAGE_DOS_HEADER)sharedMemPointer)->e_lfanew;
			//	temp_last_addr = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;
			//}
//			PerformRelocations((ULONG_PTR) sharedMemPointer, temp_last_addr);
//#ifdef _DEBUG
//			MessageBoxA(NULL, "Relocations done", "Debug", MB_OK);
//#endif
			//last_shared_mem_addr = (ULONG_PTR)sharedMemPointer;

			// call the library's entry point...
			pDllMain = (DLLMAIN)(dllEntryPoint);
#ifdef _DEBUG
			printf("DLLMain function address: %p\n", pDllMain);
#endif
			result = pDllMain((HINSTANCE)sharedMemPointer, DLL_PROCESS_ATTACH, NULL);
			// TODO recheck; when dllmain return value is false, something breaks afterwards
#ifdef _DEBUG
			if (result)
				printf("DLLMain call successful.\n");
			else
				printf("DLLMain call failed.\n");
#endif
		}
		
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
#ifdef _DEBUG
		printf("Exception occured while trying to load library:\n");
#endif
	}
	UnmapSharedMemory(sharedMemPointer);

	return result;
}


LPVOID MapSharedMemory(HANDLE sharedMemHandle){
	if (!last_shared_mem_addr){
#ifdef _DEBUG
		printf("The DLL's last base address has not been set yet. This shouldn't be the case at this point, so we don't continue.\n");
#endif
		return NULL;
	}

	// TODO this is currently just a dirty workaround
	BOOL result = VirtualFree(last_shared_mem_addr, 0, MEM_RELEASE);
#ifdef _DEBUG
	if (!result)
		printf("Freeing our blocker address failed.\n");
#endif

	LPVOID sharedMemPointer = MapViewOfFileEx(sharedMemHandle, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, 0, last_shared_mem_addr);
	if (!sharedMemPointer){
#ifdef _DEBUG
		printf("Mapping DLL failed.\n");
#endif
		return NULL;
	}
	if (last_shared_mem_addr != sharedMemPointer){
#ifdef _DEBUG
		printf("Location for DLL changed. At the moment we abort at this point as it will lead to crashes. We are working on a fix.\n");
#endif
		UnmapSharedMemory(sharedMemPointer);
		return NULL;
	}
#ifdef _DEBUG
	printf("Remapping DLL successful at: %p\n", sharedMemPointer);
#endif
	return sharedMemPointer;
}


BOOL UnmapSharedMemory(LPVOID sharedMemPointer){
	BOOL unmapSuccess = UnmapViewOfFile(sharedMemPointer);

	if (unmapSuccess){
#ifdef _DEBUG
		printf("Unmapping of DLL successfull.\n");
#endif
		// Blocks DLL's base address. Dirty workaround, will be fixed in future release
		LPVOID blockerAddress = VirtualAlloc(last_shared_mem_addr, shared_mem_size, MEM_RESERVE, PAGE_READONLY);
		if (blockerAddress != last_shared_mem_addr){
#ifdef _DEBUG
			printf("ERROR: Blocking the DLL's base address range failed. This might lead to problems.\n");
#endif
			VirtualFree(blockerAddress, 0, MEM_RELEASE);
		}
	}
#ifdef _DEBUG
	else
		printf("Unmapping of DLL failed.\n");
#endif
	return unmapSuccess;
}

DWORD GetDllInMemorySize(ULONG_PTR baseAddress){
	ULONG_PTR uiHeaderValue = baseAddress + ((PIMAGE_DOS_HEADER)baseAddress)->e_lfanew;
	return ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage;
}