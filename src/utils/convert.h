/* Utils of src - convert.h. */

#ifndef CONVERT_H
#define CONVERT_H

#include <wtypes.h>
#include <string>

namespace UtilsConvert {
	// Memory converter
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

	// String converter
	inline std::string wstr_to_str(PWSTR& wstr)
	{
		// Check args
		if (lstrlenW(wstr) <= 0) {
			return std::string();
		}

		// Calc needed wchar size and check
		int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
		if (sizeNeeded <= 0) {
			return std::string();
		}

		// Convert
		std::string strTo(sizeNeeded - 1, 0);
		if (WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &strTo[0], sizeNeeded, NULL, NULL) <= 0) {
			return std::string();
		}

		return strTo;
	}

	// Cap return code converter
	inline std::string cap_retcode_to_str(unsigned char retcode)
	{
		if (retcode & (1 << 6)) {
			return "Failed CapThreads.";
		}
		if (retcode & (1 << 5)) {
			return "Failed CapModules.";
		}
		if (retcode & (1 << 4)) {
			return "Failed CapProcess.";
		}
		if (retcode & (1 << 3)) {
			return "Failed SetMethod.";
		}
		if (retcode & (1 << 2)) {
			return "Bad args.";
		}
		if (retcode & (1 << 1)) {
			return "Unsupported.";
		}
		if (retcode & (1 << 0)) {
			return "Successfully.";
		}

		return "None.";
	}
}

#endif // CONVERT_H