#include <Windows.h>
#include <iostream>
#include <string>
#include <tchar.h>
#include <TlHelp32.h>

using namespace std;

namespace memory{
	string processName;
	HANDLE hProc;

	bool init(std::string process){
	    PROCESSENTRY32 entry;
	    entry.dwSize = sizeof(PROCESSENTRY32);
	    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	    if (Process32First(snapshot, &entry) == TRUE)
	    {
	        while (Process32Next(snapshot, &entry) == TRUE)
	        {
	            if (stricmp(entry.szExeFile, process.c_str()) == 0)
	            {  
	                hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
	                CloseHandle(hProcess);
	                return true;
	            }
	        }
	    }
	    CloseHandle(snapshot);
	    return false;
	}

	template<typename type>
	type rpm(void* address){
		type buf;
		ReadProcessMemory(hProc,address,&buf,sizeof(buf),NULL);
		return buf;
	}

	void* get_module(string moduleName){
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessID);
	    DWORD modAddy = 0;
	    if (hSnapshot != INVALID_HANDLE_VALUE)
	    {
	        MODULEENTRY32 ModuleEntry32 = { 0 };
	        ModuleEntry32.dwSize = sizeof(MODULEENTRY32);
	        if (Module32First(hSnapshot, &ModuleEntry32))
	        {
	            do
	            {
	                if (_tcscmp(ModuleEntry32.szModule, moduleName.c_str()) == 0)
	                {
	                    modAddy = (DWORD)ModuleEntry32.modBaseAddr;
	                    break;
	                }
	            } while (Module32Next(hSnapshot, &ModuleEntry32));
	        }
	        CloseHandle(hSnapshot);
	    }
	    return modAddy;
	}

	BOOLEAN compare(PVOID buffer, LPCSTR pattern, LPCSTR mask) {
		for (auto b = reinterpret_cast<PBYTE>(buffer); *mask; ++pattern, ++mask, ++b) {
			if (*mask == 'x' && *reinterpret_cast<LPCBYTE>(pattern) != *b) {
				return FALSE;
			}
		}
		return TRUE;
	}



	PBYTE pattern_scan(LPCSTR pattern, LPCSTR mask) {
		MODULEINFO info = { 0 };
		GetModuleInformation(hProc, get_module(processName), &info, sizeof(info));
		auto size = info.SizeOfImage;
		auto base = info.lpBaseOfDll;

		size -= static_cast<DWORD>(strlen(mask));
		for (auto i = 0UL; i < size; ++i) {
			auto addr = rpm<PBYTE>(base) + i;
			if (compare(addr, pattern, mask)) {
				return addr;
			}
		}
		return NULL;
	}
}
