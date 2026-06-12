/* utils.h - using for src and e.t.c. */

#ifndef CONVERT_H
#define CONVERT_H

// Using of this file includes
#include <wtypes.h>
#include <string>

namespace Utils {
	// Memory converters
	inline const bool rva_to_raw(const PIMAGE_NT_HEADERS32& ntHeader, unsigned long RVA, unsigned long& RAW)
	{
		// Check args
		if (!RVA) {
			return false;
		}

		// Jump to sections
		PIMAGE_SECTION_HEADER secHeader = IMAGE_FIRST_SECTION(ntHeader);
		if (!secHeader) {
			return false;
		}

		// Cycle for calculate RAW of RVA
		for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
			// Check diff
			if (RVA < secHeader[i].VirtualAddress || RVA >= secHeader[i].VirtualAddress + secHeader[i].SizeOfRawData) {
				continue;
			}

			// Calculate
			RAW = RVA - secHeader[i].VirtualAddress + secHeader[i].PointerToRawData;
			return true;
		}

		return false;
	}
	inline const bool rva_to_raw(const PIMAGE_NT_HEADERS64& ntHeader, unsigned long RVA, unsigned long& RAW)
	{
		// Check args
		if (!RVA) {
			return false;
		}

		// Jump to sections
		PIMAGE_SECTION_HEADER secHeader = IMAGE_FIRST_SECTION(ntHeader);
		if (!secHeader) {
			return false;
		}

		// Cycle for calculate RAW of RVA
		for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
			// Check diff
			if (RVA < secHeader[i].VirtualAddress || RVA >= secHeader[i].VirtualAddress + secHeader[i].SizeOfRawData) {
				continue;
			}

			// Calculate
			RAW = RVA - secHeader[i].VirtualAddress + secHeader[i].PointerToRawData;
			return true;
		}

		return false;
	}

	// String converters
	inline std::string WCharToChar(const wchar_t* wstr) {
		if (!wstr || lstrlenW(wstr) == 0) {
			return "";
		}

		int size = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
		if (size <= 0) {
			return "";
		}

		std::string chrStr(size - 1, 0);
		if (WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &chrStr[0], size, NULL, NULL) <= 0) {
			return "";
		}

		return chrStr;
	}
	inline std::string WCharToChar(const std::wstring& wstr) {
		return WCharToChar(wstr.c_str());
	}
}

#endif // CONVERT_H