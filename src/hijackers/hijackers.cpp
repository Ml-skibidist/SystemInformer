/* hijackers.cpp - file of code hijackers. */

// File code includes
#include "hijackers.h"
#include "../utils/utils.h"

// Using of this file includes
#include <TlHelp32.h>
#include <Psapi.h>
#include <winternl.h>
#include <fstream>

// Global data
DWORD g_QSIRAW{};

using QuerySystemInformation_t = NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS sysInfoClass, PVOID sysInfo, ULONG sysInfoLen, PULONG retLen);

__declspec(naked) NTSTATUS NTAPI QuerySystemInformation_Gate(SYSTEM_INFORMATION_CLASS sysInfoClass, PVOID sysInfo, ULONG sysInfoLen, PULONG retLen)
{
#ifdef _WIN32
	__asm {
		mov eax, g_QSIRAW
		mov edx, dword ptr[esp + 4]
		call dword ptr fs : [0xC0]
		ret 0x10
	}
#elif
	__asm {
		mov r10, rcx
		mov eax, g_QSIRAW
		syscall
		ret
	}
#endif
}

// WinAPI
bool WinAPIHijacker::CreateToolHelp32SnapshotProcesses()
{
	// Getting handle for snapshot
	HANDLE hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (!hProcSnap) {
		return false;
	}

	// First process in snapshot
	PROCESSENTRY32 procEntry32{};
	procEntry32.dwSize = sizeof(procEntry32);
	if (!Process32First(hProcSnap, &procEntry32)) {
		CloseHandle(hProcSnap);
		return false;
	}

	// Run of processes
	do {
		// Copy-struct info
		ProcessInfo procInfo{};

		// Set info
		procInfo.id = procEntry32.th32ProcessID;
		procInfo.name = procEntry32.szExeFile;

		// Getting process handle for path
		HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, procEntry32.th32ProcessID);
		if (!hProc) {
			procInfoVec_.push_back(procInfo);
			continue;
		}
		
		// Get path of process
		char szPath[MAX_PATH]{};
		DWORD szPathSize = sizeof(szPath);
		if (!QueryFullProcessImageNameA(hProc, NULL, szPath, &szPathSize)) {
			procInfoVec_.push_back(procInfo);
			continue;
		}
		procInfo.path = szPath;

		// Close path handle
		CloseHandle(hProc);
		hProc = nullptr;

		// Copy copy-struct info
		procInfoVec_.push_back(procInfo);
	} while (Process32Next(hProcSnap, &procEntry32));

	// Close snapshot handle
	CloseHandle(hProcSnap);
	hProcSnap = nullptr;

	return true;
}
bool WinAPIHijacker::CreateToolHelp32SnapshotModules(unsigned long procId)
{
	// Check args
	if (!procId) {
		return false;
	}

	// Getting handle for snapshot
	HANDLE hModSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, procId);
	if (!hModSnap) {
		return false;
	}

	// First module of process in snapshot
	MODULEENTRY32 modEntry32{};
	modEntry32.dwSize = sizeof(modEntry32);
	if (!Module32First(hModSnap, &modEntry32)) {
		return false;
	}
	
	// Run of modules
	do {
		// Copy-struct info
		ModuleInfo modInfo{};

		// Set info
		modInfo.name = modEntry32.szModule;
		modInfo.path = modEntry32.szExePath;

		// Copy copy-struct info
		modInfoVec_.push_back(modInfo);
	} while (Module32Next(hModSnap, &modEntry32));

	// Close snapshot handle
	CloseHandle(hModSnap);
	hModSnap = nullptr;

	return true;
}
bool WinAPIHijacker::CreateToolHelp32SnapshotThreads(unsigned long procId)
{
	// Check args
	if (!procId) {
		return false;
	}

	// Getting handle for snapshot
	HANDLE hThSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, procId);
	if (!hThSnap) {
		return false;
	}

	// First thread of process in snapshot
	THREADENTRY32 thEntry32{};
	thEntry32.dwSize = sizeof(thEntry32);
	if (!Thread32First(hThSnap, &thEntry32)) {
		return false;
	}

	// Run of threads
	do {
		// Copy-struct info
		ThreadInfo thInfo{};

		// Set info
		thInfo.ownerId = thEntry32.th32OwnerProcessID;

		// Copy copy-struct info
		thInfoVec_.push_back(thInfo);
	} while (Thread32Next(hThSnap, &thEntry32));

	// Close handle of snapshot
	CloseHandle(hThSnap);
	hThSnap = nullptr;

	return true;
}

bool WinAPIHijacker::K32EnumProcesses()
{
	// Vars for info
	DWORD pIDNeeded{};
	std::vector<DWORD> pID(1024);

	// Getting needed bytes and anti-exploit
	::K32EnumProcesses(nullptr, NULL, &pIDNeeded);
	if (pIDNeeded >= 1024 * 1024 * 1024) {
		return false;
	}

	// Resize info vec
	pID.resize(pIDNeeded / sizeof(DWORD));

	// Getting processes
	if (!::K32EnumProcesses(pID.data(), pID.size(), &pIDNeeded)) {
		return false;
	}

	// Run of processes
	for (size_t i = 0; i < pIDNeeded / sizeof(DWORD); i++) {
		// Check info
		if (!pID[i]) {
			continue;
		}

		// Copy-struct info
		ProcessInfo procInfo{};

		// Getting snapshot for name and path
		HANDLE hProc = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pID[i]);
		if (!hProc) {
			continue;
		}

		// Getting name
		char name[MAX_PATH]{};
		if (!::K32GetModuleBaseNameA(hProc, nullptr, name, sizeof(name))) {
			CloseHandle(hProc);
			hProc = nullptr;

			continue;
		}
		procInfo.name = name;

		// Getting path
		char path[MAX_PATH]{};
		if (!::K32GetModuleFileNameExA(hProc, nullptr, path, sizeof(path))) {
			procInfoVec_.push_back(procInfo);

			CloseHandle(hProc);
			hProc = nullptr;

			continue;
		}
		procInfo.path = path;

		// Close name and path handle
		CloseHandle(hProc);
		hProc = nullptr;

		// Copy copy-struct info
		procInfoVec_.push_back(procInfo);
	}

	return true;
}
bool WinAPIHijacker::K32EnumProcessModules(unsigned long procId)
{
	// Check args
	if (!procId) {
		return false;
	}

	// Getting snapshot for modules
	HANDLE hProc = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, procId);
	if (!hProc) {
		return false;
	}

	// Vars for info
	DWORD hModsNeeded{};
	std::vector<HMODULE> hMods(1024);

	// Getting needed bytes and anti-exploit
	::K32EnumProcessModules(hProc, nullptr, NULL, &hModsNeeded);
	if (hModsNeeded >= 1024 * 1024 * 1024) {
		CloseHandle(hProc);
		return false;
	}

	// Resize info vec
	hMods.resize(hModsNeeded / sizeof(HMODULE));

	// Getting modules
	if (!::K32EnumProcessModules(hProc, hMods.data(), hMods.size(), &hModsNeeded)) {
		CloseHandle(hProc);
		return false;
	}

	// Close handle for modules
	CloseHandle(hProc);
	hProc = nullptr;

	// Run of modules
	for (size_t i = 0; i < hModsNeeded / sizeof(DWORD); i++) {
		// Check info
		if (!hMods[i]) {
			continue;
		}

		// Copy-struct info
		ModuleInfo modInfo{};

		// Getting name
		char name[MAX_PATH]{};
		if (!::K32GetModuleBaseNameA(hMods[i], nullptr, name, sizeof(name))) {
			continue;
		}
		modInfo.name = name;

		// Getting path
		char path[MAX_PATH]{};
		if (!::K32GetModuleFileNameExA(hMods[i], nullptr, path, sizeof(path))) {
			modInfoVec_.push_back(modInfo);
			continue;
		}
		modInfo.path = path;

		// Copy copy-struct
		modInfoVec_.push_back(modInfo);
	}

	return true;
}
bool WinAPIHijacker::K32EnumProcessModulesEx(unsigned long procId)
{
	// Check args
	if (!procId) {
		return false;
	}

	// Getting snapshot for modules
	HANDLE hProc = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, procId);
	if (!hProc) {
		return false;
	}

	// Vars for info
	DWORD hModsNeeded{};
	std::vector<HMODULE> hMods(1024);

	// Getting needed bytes and anti-exploit
	::K32EnumProcessModulesEx(hProc, nullptr, NULL, &hModsNeeded, NULL);
	if (hModsNeeded >= 1024 * 1024 * 1024) {
		CloseHandle(hProc);
		return false;
	}

	// Resize info vec
	hMods.resize(hModsNeeded / sizeof(HMODULE));

	// Getting modules
	if (!::K32EnumProcessModulesEx(hProc, hMods.data(), hMods.size(), &hModsNeeded, NULL)) {
		CloseHandle(hProc);
		return false;
	}

	// Close handle for modules
	CloseHandle(hProc);
	hProc = nullptr;

	// Run of modules
	for (size_t i = 0; i < hModsNeeded / sizeof(DWORD); i++) {
		// Check info
		if (!hMods[i]) {
			continue;
		}

		// Copy-struct info
		ModuleInfo modInfo{};

		// Getting name
		char name[MAX_PATH]{};
		if (!::K32GetModuleBaseNameA(hMods[i], nullptr, name, sizeof(name))) {
			continue;
		}
		modInfo.name = name;

		// Getting path
		char path[MAX_PATH]{};
		if (!::K32GetModuleFileNameExA(hMods[i], nullptr, path, sizeof(path))) {
			modInfoVec_.push_back(modInfo);
			continue;
		}
		modInfo.path = path;

		// Copy copy-struct
		modInfoVec_.push_back(modInfo);
	}

	return true;
}

bool WinAPIHijacker::CapProcesses()
{
	// Needable method for bins
	switch (method_) {
	case (WINAPI_CTH32S): {
		return CreateToolHelp32SnapshotProcesses();
	}
	case (WINAPI_K32E): {
		return K32EnumProcesses();
	}
	case (WINAPI_K32EE): {
		return false;
	}
	default: {
		return CreateToolHelp32SnapshotProcesses();
	}
	}
}
bool WinAPIHijacker::CapModules(unsigned long procId)
{
	// Needable method for libs
	switch (method_) {
	case (WINAPI_CTH32S): {
		return CreateToolHelp32SnapshotModules(procId);
	}
	case (WINAPI_K32E): {
		return K32EnumProcessModules(procId);
	}
	case (WINAPI_K32EE): {
		return K32EnumProcessModulesEx(procId);
	}
	default: {
		return CreateToolHelp32SnapshotModules(procId);
	}
	}
}
bool WinAPIHijacker::CapThreads(unsigned long procId)
{
	// Needable method for threads
	switch (method_) {
	case (WINAPI_CTH32S): {
		return CreateToolHelp32SnapshotThreads(procId);
	}
	case (WINAPI_K32E): {
		return false;
	}
	case (WINAPI_K32EE): {
		return false;
	}
	default: {
		return CreateToolHelp32SnapshotThreads(procId);
	}
	}
}

// NtDll
bool NtDllHijacker::QueryInformationProcessDefaultProcesses()
{
	// Getting "ntdll.dll" lib
	HMODULE ntdllLib = GetModuleHandleA("ntdll.dll");
	if (!ntdllLib) {
		return false;
	}
	// Find "ZwQuerySystemInformation"\"NtQuerySystemInformation" funcs in lib
	QuerySystemInformation_t QuerySystemInformation = reinterpret_cast<QuerySystemInformation_t>(GetProcAddress(ntdllLib, "ZwQuerySystemInformation"));
	if (!QuerySystemInformation) {
		QuerySystemInformation = reinterpret_cast<QuerySystemInformation_t>(GetProcAddress(ntdllLib, "NtQuerySystemInformation"));
		if (!QuerySystemInformation) {
			return false;
		}
	}

	// Vars for info
	DWORD pSysProcInfoVecLen{};
	std::vector<byte> pSysProcInfoVec(1024);

	// Getting needed bytes and anti-exploit
	QuerySystemInformation(SystemProcessInformation, nullptr, NULL, &pSysProcInfoVecLen);
	if (pSysProcInfoVecLen >= 1024 * 1024 * 1024) {
		return false;
	}

	// Resize info vec
	pSysProcInfoVec.resize(pSysProcInfoVecLen);

	// Getting processes
	if (!NT_SUCCESS(QuerySystemInformation(SystemProcessInformation, pSysProcInfoVec.data(), pSysProcInfoVec.size(), &pSysProcInfoVecLen))) {
		return false;
	}

	// Run of processes
	PSYSTEM_PROCESS_INFORMATION pSysProcInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(pSysProcInfoVec.data());
	while (pSysProcInfo) {
		// Copy-struct info
		ProcessInfo procInfo{};
		
		// Set info
		procInfo.id = reinterpret_cast<DWORD>(pSysProcInfo->UniqueProcessId);
		procInfo.name = Utils::WCharToChar(pSysProcInfo->ImageName.Buffer);

		// Getting path handle
		HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, procInfo.id);
		if (!hProc) {
			// Copy copy-struct
			procInfoVec_.push_back(procInfo);

			// Jmp to next data
			if (!pSysProcInfo->NextEntryOffset) {
				break;
			}
			pSysProcInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<BYTE*>(pSysProcInfo) + pSysProcInfo->NextEntryOffset);
		
			continue;
		}

		// Getting path
		char szPath[MAX_PATH]{};
		DWORD szPathSize = sizeof(szPath);
		if (!QueryFullProcessImageNameA(hProc, NULL, szPath, &szPathSize)) {
			procInfoVec_.push_back(procInfo);

			// Close path handle
			CloseHandle(hProc);
			hProc = nullptr;

			// Jmp to next data
			if (!pSysProcInfo->NextEntryOffset) {
				break;
			}
			pSysProcInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<BYTE*>(pSysProcInfo) + pSysProcInfo->NextEntryOffset);
		
			continue;
		}
		procInfo.path = szPath;

		// Copy copy-struct
		procInfoVec_.push_back(procInfo);

		// Close path handle
		CloseHandle(hProc);
		hProc = nullptr;

		// Jmp to next data
		if (!pSysProcInfo->NextEntryOffset) {
			break;
		}
		pSysProcInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<BYTE*>(pSysProcInfo) + pSysProcInfo->NextEntryOffset);
	}

	return true;
}
bool NtDllHijacker::QueryInformationProcessDefaultThreads(unsigned long procId)
{
	// Getting "ntdll.dll" lib
	HMODULE ntdllLib = GetModuleHandleA("ntdll.dll");
	if (!ntdllLib) {
		return false;
	}
	// Find "ZwQuerySystemInformation"\"NtQuerySystemInformation" funcs in lib
	QuerySystemInformation_t QuerySystemInformation = reinterpret_cast<QuerySystemInformation_t>(GetProcAddress(ntdllLib, "ZwQuerySystemInformation"));
	if (!QuerySystemInformation) {
		QuerySystemInformation = reinterpret_cast<QuerySystemInformation_t>(GetProcAddress(ntdllLib, "NtQuerySystemInformation"));
		if (!QuerySystemInformation) {
			return false;
		}
	}

	// Vars for info
	DWORD pSysProcInfoVecLen{};
	std::vector<byte> pSysProcInfoVec(1024);

	// Getting needed bytes and anti-exploit
	QuerySystemInformation(SystemProcessInformation, nullptr, NULL, &pSysProcInfoVecLen);
	if (pSysProcInfoVecLen >= 1024 * 1024 * 1024) {
		return false;
	}

	// Resize info vec
	pSysProcInfoVec.resize(pSysProcInfoVecLen);

	// Getting processes
	if (!NT_SUCCESS(QuerySystemInformation(SystemProcessInformation, pSysProcInfoVec.data(), pSysProcInfoVec.size(), &pSysProcInfoVecLen))) {
		return false;
	}

	// Run of processes
	PSYSTEM_PROCESS_INFORMATION pSysProcInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(pSysProcInfoVec.data());
	while (pSysProcInfo) {
		// Check for needed process id
		DWORD currProcId = HandleToUlong(pSysProcInfo->UniqueProcessId);
		if (currProcId == procId) {
			// Getting thread info
			PSYSTEM_THREAD_INFORMATION pSysThreadInfo = reinterpret_cast<PSYSTEM_THREAD_INFORMATION>(pSysProcInfo + 1);
			if (!pSysThreadInfo) {
				// Jmp to next data
				if (!pSysProcInfo->NextEntryOffset) {
					break;
				}
				pSysProcInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<unsigned char*>(pSysProcInfo) + pSysProcInfo->NextEntryOffset);
				
				continue;
			}

			// Run of threads
			for (size_t i = 0; i < pSysProcInfo->NumberOfThreads; i++) {
				// Copy-struct info
				ThreadInfo thInfo{};

				// Set info
				thInfo.ownerId = currProcId;

				// Copy copy-struct
				thInfoVec_.push_back(thInfo);
			}

			// Exit from cycle
			break;
		}

		// Jmp to next data
		if (!pSysProcInfo->NextEntryOffset) {
			break;
		}
		pSysProcInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<unsigned char*>(pSysProcInfo) + pSysProcInfo->NextEntryOffset);
	}

	return true;
}

bool NtDllHijacker::QueryInformationProcessBasicProcesses()
{
	// Getting "ntdll.dll" lib
	HMODULE ntdllLib = GetModuleHandleA("ntdll.dll");
	if (!ntdllLib) {
		return false;
	}
	// Find "ZwQuerySystemInformation"\"NtQuerySystemInformation" funcs in lib
	QuerySystemInformation_t QuerySystemInformation = reinterpret_cast<QuerySystemInformation_t>(GetProcAddress(ntdllLib, "ZwQuerySystemInformation"));
	if (!QuerySystemInformation) {
		QuerySystemInformation = reinterpret_cast<QuerySystemInformation_t>(GetProcAddress(ntdllLib, "NtQuerySystemInformation"));
		if (!QuerySystemInformation) {
			return false;
		}
	}

	// Vars for info
	DWORD pSysProcInfoVecLen{};
	std::vector<byte> pSysProcInfoVec(1024);

	// Getting needed bytes and anti-exploit
	QuerySystemInformation(SystemBasicProcessInformation, nullptr, NULL, &pSysProcInfoVecLen);
	if (pSysProcInfoVecLen >= 1024 * 1024 * 1024) {
		return false;
	}

	// Resize info vec
	pSysProcInfoVec.resize(pSysProcInfoVecLen);

	// Getting processes
	if (!NT_SUCCESS(QuerySystemInformation(SystemBasicProcessInformation, pSysProcInfoVec.data(), pSysProcInfoVec.size(), &pSysProcInfoVecLen))) {
		return false;
	}

	// Run of processes
	PSYSTEM_PROCESS_INFORMATION pSysProcInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(pSysProcInfoVec.data());
	while (pSysProcInfo) {
		// Copy-struct info
		ProcessInfo procInfo{};

		// Set info
		procInfo.id = reinterpret_cast<DWORD>(pSysProcInfo->UniqueProcessId);
		procInfo.name = Utils::WCharToChar(pSysProcInfo->ImageName.Buffer);

		// Getting path handle
		HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, procInfo.id);
		if (!hProc) {
			// Copy copy-struct
			procInfoVec_.push_back(procInfo);

			// Jmp to next data
			if (!pSysProcInfo->NextEntryOffset) {
				break;
			}
			pSysProcInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<BYTE*>(pSysProcInfo) + pSysProcInfo->NextEntryOffset);

			continue;
		}

		// Getting path
		char szPath[MAX_PATH]{};
		DWORD szPathSize = sizeof(szPath);
		if (!QueryFullProcessImageNameA(hProc, NULL, szPath, &szPathSize)) {
			// Copy copy-struct
			procInfoVec_.push_back(procInfo);

			// Close path handle
			CloseHandle(hProc);
			hProc = nullptr;

			// Jmp to next data
			if (!pSysProcInfo->NextEntryOffset) {
				break;
			}
			pSysProcInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<BYTE*>(pSysProcInfo) + pSysProcInfo->NextEntryOffset);

			continue;
		}
		procInfo.path = szPath;

		// Copy copy-struct
		procInfoVec_.push_back(procInfo);

		// Close path handle
		CloseHandle(hProc);
		hProc = nullptr;

		// Jmp to next data
		if (!pSysProcInfo->NextEntryOffset) {
			break;
		}
		pSysProcInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<BYTE*>(pSysProcInfo) + pSysProcInfo->NextEntryOffset);
	}

	return true;
}

bool NtDllHijacker::CapProcesses()
{
	// Needable method for bins
	switch (method_) {
	case (NTDLL_QIPD):
		return QueryInformationProcessDefaultProcesses();
	case (NTDLL_QIPB):
		return QueryInformationProcessBasicProcesses();
	default:
		return QueryInformationProcessDefaultProcesses();
	}
}
bool NtDllHijacker::CapModules(unsigned long procId)
{
	// Needable method for libs
	switch (method_) {
	case (NTDLL_QIPD):
		return false;
	case (NTDLL_QIPB):
		return false;
	default:
		return false;
	}
}
bool NtDllHijacker::CapThreads(unsigned long procId)
{
	// Needable method for threads
	switch (method_) {
	case (NTDLL_QIPD):
		return QueryInformationProcessDefaultThreads(procId);
	case (NTDLL_QIPB):
		return false;
	default:
		return QueryInformationProcessDefaultThreads(procId);
	}
}

// SysCalls
bool SysCallHijacker::GetSCN(std::string ntdllFuncName, DWORD& SCN)
{
	// Getting system dir
	char sysDir[MAX_PATH]{};
	if (!GetSystemDirectoryA(sysDir, sizeof(sysDir))) {
		return false;
	}

	// Finding "ntdll.dll"
	const std::string ntdllPath = sysDir + static_cast<std::string>("\\ntdll.dll");

	// Try open file binary
	std::ifstream ntdllFile(ntdllPath.c_str(), std::ios::binary | std::ios::ate);
	if (!ntdllFile.is_open()) {
		return false;
	}

	// Capture size file
	std::streamsize ntdllFileSize = ntdllFile.tellg();
	ntdllFile.seekg(0, std::ios::beg);

	// Allocate vec with size of size file
	std::vector<char> ntdllFileBuff(ntdllFileSize);
	if (!ntdllFile.read(ntdllFileBuff.data(), ntdllFileSize)) {
		ntdllFile.close();
		return false;
	}

	// Close file
	ntdllFile.close();

	// Dos header of file
	PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(ntdllFileBuff.data());
	if (!dosHeader || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return false;
	}
	// Nt header of file
	PIMAGE_NT_HEADERS ntHeaderChecker = reinterpret_cast<PIMAGE_NT_HEADERS>(ntdllFileBuff.data() + dosHeader->e_lfanew);
	if (!ntHeaderChecker || ntHeaderChecker->Signature != IMAGE_NT_SIGNATURE) {
		return false;
	}

	// Logic for x64
	if (ntHeaderChecker->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
		PIMAGE_NT_HEADERS64 ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(ntdllFileBuff.data() + dosHeader->e_lfanew);

		DWORD addrExportRAW{};
		if (!Utils::rva_to_raw(ntHeader, ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, addrExportRAW)) {
			return false;
		}
		PIMAGE_EXPORT_DIRECTORY addrExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(ntdllFileBuff.data() + addrExportRAW);
		if (!addrExportDir) {
			return false;
		}

		DWORD namesRAW{};
		if (!Utils::rva_to_raw(ntHeader, addrExportDir->AddressOfNames, namesRAW)) {
			return false;
		}
		DWORD* addrNamesRAW = reinterpret_cast<DWORD*>(ntdllFileBuff.data() + namesRAW);
		if (!addrNamesRAW) {
			return false;
		}

		DWORD ordinalRVACaptured = 0xFFFFFFFF;

		for (DWORD i = 0; i < addrExportDir->NumberOfNames; i++) {
			DWORD nameRVA = addrNamesRAW[i];
			if (!nameRVA) {
				continue;
			}

			DWORD nameRAW{};
			if (!Utils::rva_to_raw(ntHeader, nameRVA, nameRAW)) {
				continue;
			}

			char* funcName = reinterpret_cast<char*>(ntdllFileBuff.data() + nameRAW);
			if (!funcName || !strlen(funcName)) {
				continue;
			}
			if (strcmp(funcName, ntdllFuncName.c_str())) {
				continue;
			}

			ordinalRVACaptured = i;
			break;
		}

		if (ordinalRVACaptured == 0xFFFFFFFF) {
			return false;
		}

		DWORD ordsRAW{};
		if (!Utils::rva_to_raw(ntHeader, addrExportDir->AddressOfNameOrdinals, ordsRAW)) {
			return false;
		}
		WORD* addrOrdsRAW = reinterpret_cast<WORD*>(ntdllFileBuff.data() + ordsRAW);
		if (!addrOrdsRAW) {
			return false;
		}

		WORD ordVal = addrOrdsRAW[ordinalRVACaptured];
		if (!ordVal) {
			return false;
		}

		DWORD funcsRAW{};
		if (!Utils::rva_to_raw(ntHeader, addrExportDir->AddressOfFunctions, funcsRAW)) {
			return false;
		}
		DWORD* addrFuncsRAW = reinterpret_cast<DWORD*>(ntdllFileBuff.data() + funcsRAW);
		if (!addrFuncsRAW) {
			return false;
		}

		DWORD addrNeedRVA = addrFuncsRAW[ordVal];
		if (!addrNeedRVA) {
			return false;
		}
		DWORD addrNeedRAW{};
		if (!Utils::rva_to_raw(ntHeader, addrNeedRVA, addrNeedRAW)) {
			return false;
		}

		const byte* funcBytes = reinterpret_cast<const byte*>(ntdllFileBuff.data() + addrNeedRAW);
		if (!funcBytes) {
			return false;
		}

		size_t scanLen = ntdllFileBuff.size() - addrNeedRAW;
		if (!scanLen) {
			return false;
		}

		DWORD SCNCaptured{};

		for (size_t i = 0; i < scanLen - 1; i++) {
			if (funcBytes[i] == 0xC3 || funcBytes[i] == 0xCC) {
				break;
			}

			if (i + 7 < scanLen && funcBytes[i] == 0x44 && funcBytes[i + 1] == 0x8B && funcBytes[i + 2] == 0xD2) {
				if (funcBytes[i + 3] == 0xB8) {
					SCNCaptured = *reinterpret_cast<const DWORD*>(&funcBytes[i + 1]);
					break;
				}
			}
		}

		if (!SCNCaptured) {
			return false;
		}

		SCN = SCNCaptured;
		return true;
	}
	// Logic for x32
	else {
		PIMAGE_NT_HEADERS32 ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS32>(ntdllFileBuff.data() + dosHeader->e_lfanew);

		DWORD addrExportRAW{};
		if (!Utils::rva_to_raw(ntHeader, ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, addrExportRAW)) {
			return false;
		}
		PIMAGE_EXPORT_DIRECTORY addrExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(ntdllFileBuff.data() + addrExportRAW);
		if (!addrExportDir) {
			return false;
		}

		DWORD namesRAW{};
		if (!Utils::rva_to_raw(ntHeader, addrExportDir->AddressOfNames, namesRAW)) {
			return false;
		}
		DWORD* addrNamesRAW = reinterpret_cast<DWORD*>(ntdllFileBuff.data() + namesRAW);
		if (!addrNamesRAW) {
			return false;
		}

		DWORD ordinalRVACaptured = 0xFFFFFFFF;

		for (DWORD i = 0; i < addrExportDir->NumberOfNames; i++) {
			DWORD nameRVA = addrNamesRAW[i];
			if (!nameRVA) {
				continue;
			}
			DWORD nameRAW{};
			if (!Utils::rva_to_raw(ntHeader, nameRVA, nameRAW)) {
				continue;
			}

			char* funcName = reinterpret_cast<char*>(ntdllFileBuff.data() + nameRAW);
			if (!funcName || !strlen(funcName)) {
				continue;
			}
			if (strcmp(funcName, ntdllFuncName.c_str())) {
				continue;
			}

			ordinalRVACaptured = i;
			break;
		}

		if (ordinalRVACaptured == 0xFFFFFFFF) {
			return false;
		}

		DWORD ordsRAW{};
		if (!Utils::rva_to_raw(ntHeader, addrExportDir->AddressOfNameOrdinals, ordsRAW)) {
			return false;
		}
		WORD* addrOrdsRAW = reinterpret_cast<WORD*>(ntdllFileBuff.data() + ordsRAW);
		if (!addrOrdsRAW) {
			return false;
		}

		WORD ordVal = addrOrdsRAW[ordinalRVACaptured];
		if (!ordVal) {
			return false;
		}

		DWORD funcsRAW{};
		if (!Utils::rva_to_raw(ntHeader, addrExportDir->AddressOfFunctions, funcsRAW)) {
			return false;
		}
		DWORD* addrFuncsRAW = reinterpret_cast<DWORD*>(ntdllFileBuff.data() + funcsRAW);
		if (!addrFuncsRAW) {
			return false;
		}

		DWORD addrNeedRVA = addrFuncsRAW[ordVal];
		if (!addrNeedRVA) {
			return false;
		}
		DWORD addrNeedRAW{};
		if (!Utils::rva_to_raw(ntHeader, addrNeedRVA, addrNeedRAW)) {
			return false;
		}

		const byte* funcBytes = reinterpret_cast<const byte*>(ntdllFileBuff.data() + addrNeedRAW);
		if (!funcBytes) {
			return false;
		}

		size_t scanLen = ntdllFileBuff.size() - addrNeedRAW;
		if (!scanLen) {
			return false;
		}

		DWORD SCNCaptured{};

		for (size_t i = 0; i < scanLen - 1; i++) {
			if (funcBytes[i] == 0xC3 || funcBytes[i] == 0xCC) {
				break;
			}

			if (funcBytes[i] == 0xB8 && i + 4 < scanLen) {
				SCNCaptured = *reinterpret_cast<const DWORD*>(&funcBytes[i + 1]);
				break;
			}
		}

		if (!SCNCaptured) {
			return false;
		}

		SCN = SCNCaptured;
		return true;
	}
}
bool SysCallHijacker::GetGJT(std::string ntdllFuncName, DWORD& GJT)
{
	return false;	// TODO: gadjet
}

bool SysCallHijacker::QueryInformationProcessDefaultProcesses()
{
	// Getting needable SCN(SSN) in this functions by "ntdll.dll" file
	if (!GetSCN("ZwQuerySystemInformation", g_QSIRAW)) {
		if (!GetSCN("NtQuerySystemInformation", g_QSIRAW)) {
			return false;
		}
	}

	// Vars for info
	DWORD pSysProcInfoVecLen{};
	std::vector<byte> pSysProcInfoVec(1024);

	// Getting needable bytes and anti-exploit
	QuerySystemInformation_Gate(SystemProcessInformation, nullptr, NULL, &pSysProcInfoVecLen);
	if (pSysProcInfoVecLen >= 1024 * 1024 * 1024) {
		return false;
	}

	// Resize info vec
	pSysProcInfoVec.resize(pSysProcInfoVecLen);

	// Getting processes
	if (!NT_SUCCESS(QuerySystemInformation_Gate(SystemProcessInformation, pSysProcInfoVec.data(), pSysProcInfoVec.size(), &pSysProcInfoVecLen))) {
		return false;
	}

	// Run of processes
	PSYSTEM_PROCESS_INFORMATION pSysProcInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(pSysProcInfoVec.data());
	while (pSysProcInfo) {
		// Copy-struct info
		ProcessInfo procInfo{};

		// Set info
		procInfo.id = reinterpret_cast<DWORD>(pSysProcInfo->UniqueProcessId);
		procInfo.name = Utils::WCharToChar(pSysProcInfo->ImageName.Buffer);

		// Getting path handle
		HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, procInfo.id);
		if (!hProc) {
			// Copy-struct info
			procInfoVec_.push_back(procInfo);

			// Jmp to next data
			if (!pSysProcInfo->NextEntryOffset) {
				break;
			}
			pSysProcInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<BYTE*>(pSysProcInfo) + pSysProcInfo->NextEntryOffset);

			continue;
		}

		// Getting path
		char szPath[MAX_PATH]{};
		DWORD szPathSize = sizeof(szPath);
		if (!QueryFullProcessImageNameA(hProc, NULL, szPath, &szPathSize)) {
			// Copy-struct info
			procInfoVec_.push_back(procInfo);

			// Close path handle
			CloseHandle(hProc);
			hProc = nullptr;

			// Jmp to next data
			if (!pSysProcInfo->NextEntryOffset) {
				break;
			}
			pSysProcInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<BYTE*>(pSysProcInfo) + pSysProcInfo->NextEntryOffset);

			continue;
		}
		procInfo.path = szPath;

		// Copy copy-struct
		procInfoVec_.push_back(procInfo);

		// Close path handle
		CloseHandle(hProc);
		hProc = nullptr;

		// Jmp to next data
		if (!pSysProcInfo->NextEntryOffset) {
			break;
		}
		pSysProcInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<BYTE*>(pSysProcInfo) + pSysProcInfo->NextEntryOffset);
	}

	return true;
}
bool SysCallHijacker::QueryInformationProcessDefaultThreads(unsigned long procId)
{
	// Getting needable SCN(SSN) in this functions by "ntdll.dll" file
	if (!GetSCN("ZwQuerySystemInformation", g_QSIRAW)) {
		if (!GetSCN("NtQuerySystemInformation", g_QSIRAW)) {
			return false;
		}
	}

	// Vars for info
	DWORD pSysProcInfoVecLen{};
	std::vector<byte> pSysProcInfoVec(1024);

	// Getting needable bytes and anti-exploit
	QuerySystemInformation_Gate(SystemProcessInformation, nullptr, NULL, &pSysProcInfoVecLen);
	if (pSysProcInfoVecLen >= 1024 * 1024 * 1024) {
		return false;
	}

	// Resize info vec
	pSysProcInfoVec.resize(pSysProcInfoVecLen);

	// Getting processes
	if (!NT_SUCCESS(QuerySystemInformation_Gate(SystemProcessInformation, pSysProcInfoVec.data(), pSysProcInfoVec.size(), &pSysProcInfoVecLen))) {
		return false;
	}

	// Run of processes
	PSYSTEM_PROCESS_INFORMATION pSysProcInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(pSysProcInfoVec.data());
	while (pSysProcInfo) {
		// Check for needed process id
		DWORD currProcId = HandleToUlong(pSysProcInfo->UniqueProcessId);
		if (currProcId == procId) {
			// Getting thread info
			PSYSTEM_THREAD_INFORMATION pSysThreadInfo = reinterpret_cast<PSYSTEM_THREAD_INFORMATION>(pSysProcInfo + 1);
			if (!pSysThreadInfo) {
				// Jmp to next data
				if (!pSysProcInfo->NextEntryOffset) {
					break;
				}
				pSysProcInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<unsigned char*>(pSysProcInfo) + pSysProcInfo->NextEntryOffset);

				continue;
			}

			// Run of threads
			for (int i = 0; i < pSysProcInfo->NumberOfThreads; i++) {
				ThreadInfo thInfo{};
				thInfo.ownerId = currProcId;

				thInfoVec_.push_back(thInfo);
			}

			// Exit from cycle
			break;
		}

		// Jmp to next data
		if (!pSysProcInfo->NextEntryOffset) {
			break;
		}
		pSysProcInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<unsigned char*>(pSysProcInfo) + pSysProcInfo->NextEntryOffset);
	}

	return true;
}

bool SysCallHijacker::QueryInformationProcessBasicProcesses()
{
	// Getting needable SCN(SSN) in this functions by "ntdll.dll" file
	if (!GetSCN("ZwQuerySystemInformation", g_QSIRAW)) {
		if (!GetSCN("NtQuerySystemInformation", g_QSIRAW)) {
			return false;
		}
	}

	// Vars for info
	DWORD pSysProcInfoVecLen{};
	std::vector<byte> pSysProcInfoVec(1024);

	// Getting needable bytes and anti-exploit (1MB RAM)
	QuerySystemInformation_Gate(SystemBasicProcessInformation, nullptr, NULL, &pSysProcInfoVecLen);
	if (pSysProcInfoVecLen >= 1024 * 1024) {
		return false;
	}

	// Resize info vec
	pSysProcInfoVec.resize(pSysProcInfoVecLen);

	// Getting processes
	if (!NT_SUCCESS(QuerySystemInformation_Gate(SystemBasicProcessInformation, pSysProcInfoVec.data(), pSysProcInfoVec.size(), &pSysProcInfoVecLen))) {
		return false;
	}

	// Run of processes
	PSYSTEM_BASICPROCESS_INFORMATION pSysBasicProcInfo = reinterpret_cast<PSYSTEM_BASICPROCESS_INFORMATION>(pSysProcInfoVec.data());
	while (pSysBasicProcInfo) {
		// Copy-struct info
		ProcessInfo procInfo{};

		// Set info
		procInfo.id = reinterpret_cast<DWORD>(pSysBasicProcInfo->UniqueProcessId);
		procInfo.name = Utils::WCharToChar(pSysBasicProcInfo->ImageName.Buffer);

		// Getting path handle
		HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, procInfo.id);
		if (!hProc) {
			// Copy-struct info
			procInfoVec_.push_back(procInfo);

			// Jmp to next data
			if (!pSysBasicProcInfo->NextEntryOffset) {
				break;
			}
			pSysBasicProcInfo = reinterpret_cast<PSYSTEM_BASICPROCESS_INFORMATION>(reinterpret_cast<byte*>(pSysBasicProcInfo) + pSysBasicProcInfo->NextEntryOffset);

			continue;
		}

		// Getting path
		char szPath[MAX_PATH]{};
		DWORD szPathSize = sizeof(szPath);
		if (!QueryFullProcessImageNameA(hProc, NULL, szPath, &szPathSize)) {
			// Copy-struct info
			procInfoVec_.push_back(procInfo);

			// Close path handle
			CloseHandle(hProc);
			hProc = nullptr;

			// Jmp to next data
			if (!pSysBasicProcInfo->NextEntryOffset) {
				break;
			}
			pSysBasicProcInfo = reinterpret_cast<PSYSTEM_BASICPROCESS_INFORMATION>(reinterpret_cast<byte*>(pSysBasicProcInfo) + pSysBasicProcInfo->NextEntryOffset);

			continue;
		}
		procInfo.path = szPath;

		// Copy copy-struct
		procInfoVec_.push_back(procInfo);

		// Close path handle
		CloseHandle(hProc);
		hProc = nullptr;

		// Jmp to next data
		if (!pSysBasicProcInfo->NextEntryOffset) {
			break;
		}
		pSysBasicProcInfo = reinterpret_cast<PSYSTEM_BASICPROCESS_INFORMATION>(reinterpret_cast<byte*>(pSysBasicProcInfo) + pSysBasicProcInfo->NextEntryOffset);
	}

	return true;
}

bool SysCallHijacker::CapProcesses()
{
	// Needable method for bins
	switch (method_) {
	case (SYSCALL_QIPD):
		return QueryInformationProcessDefaultProcesses();
	case (SYSCALL_QIPB):
		return QueryInformationProcessBasicProcesses();
	default:
		return QueryInformationProcessDefaultProcesses();
	}
}
bool SysCallHijacker::CapModules(unsigned long procId)
{
	// Needable method for libs
	switch (method_) {
	case (SYSCALL_QIPD):
		return false;
	case (SYSCALL_QIPB):
		return false;
	default:
		return false;
	}
}
bool SysCallHijacker::CapThreads(unsigned long procId)
{
	// Needable method for threads
	switch (method_) {
	case (SYSCALL_QIPD):
		return QueryInformationProcessDefaultThreads(procId);
	case (SYSCALL_QIPB):
		return false;
	default:
		return QueryInformationProcessDefaultThreads(procId);
	}
}

// Manager
void ManagerHijackers::SetHijacker(SwitchesEnum switcher)
{
	// Set needable datatype, default is WinAPI
	switch (switcher) {
		case (SWITCH_WINAPI): { ihijacker_ = std::make_unique<WinAPIHijacker>(); break; }
		case (SWITCH_NTDLL): { ihijacker_ = std::make_unique<NtDllHijacker>(); break; }
		case (SWITCH_SYSCALL): { ihijacker_ = std::make_unique<SysCallHijacker>(); break; }
		default: { ihijacker_ = std::make_unique<WinAPIHijacker>(); }
	}
}
IHijackers* ManagerHijackers::GetHijacker() {
	return ihijacker_.get();
}

CapRetCodesEnum ManagerHijackers::Cap(unsigned char method, CapsEnum cap, unsigned long procId)
{
	// Return value
	CapRetCodesEnum ret = CAP_RETCODE_SUCCESS;

	// Check unsupported method and caps
	if ((method == WINAPI_K32E || method == WINAPI_K32EE) && (cap & CAP_THREADS) ||
		method == WINAPI_K32EE && (cap & CAP_PROCESSES) ||		
		(method == NTDLL_QIPD || method == NTDLL_QIPB) && (cap & CAP_MODULES) ||
		method == NTDLL_QIPB && (cap & CAP_THREADS) ||		
		(method == SYSCALL_QIPD || method == SYSCALL_QIPB) && (cap & CAP_MODULES) ||
		method == SYSCALL_QIPB && (cap & CAP_THREADS)) {
		ret = CAP_RETCODE_UNSUPPORTED;
		return ret;
	}

	// Check args
	if (((cap & CAP_MODULES) || (cap & CAP_THREADS)) && !procId) {
		ret = CAP_RETCODE_BAD_ARGS;
		return ret;
	}

	// Set current method
	ihijacker_->SetMethod(method);

	// Try bins list
	if (cap & CAP_PROCESSES) {
		if (!ihijacker_->CapProcesses()) {
			ret = static_cast<CapRetCodesEnum>(ret | CAP_RETCODE_FAILED_CAP_PROCESSES);
		}
	}
	// Try libs list
	if (cap & CAP_MODULES) {
		if (!ihijacker_->CapModules(procId)) {
			ret = static_cast<CapRetCodesEnum>(ret | CAP_RETCODE_FAILED_CAP_MODULES);
		}
	}
	// Try threads list
	if (cap & CAP_THREADS) {
		if (!ihijacker_->CapThreads(procId)) {
			ret = static_cast<CapRetCodesEnum>(ret | CAP_RETCODE_FAILED_CAP_THREADS);
		}
	}

	return ret;
}