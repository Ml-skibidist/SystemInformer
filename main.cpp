/* main.cpp - entrypoint. */

// Using of this file includes
#include <iostream>

// File code includes
#include "src/hijackers/hijackers.h"
#include "src/utils/utils.h"

// Main EntryPoint
int main()
{
    /* WINAPI */

    // Manager of hijackers, started with WinAPIHijackers
    ManagerHijackers hijackersManager_{ std::make_unique<WinAPIHijacker>() };

    // Capture and retcode check
    unsigned char capRetCode = hijackersManager_.Cap(WINAPI_CTH32S, CAP_PROCESSES, NULL);
    if (!CAP_RETCODE_IS_SUCCESS(capRetCode)) {
        printf("%s. (%lu)\n", hijackersManager_.cap_retcode_to_str(capRetCode).c_str(), capRetCode);

        std::cin.get();
        return 0;
    }

    // Pushing procInfo and check
    std::vector<ProcessInfo> procInfo = hijackersManager_.GetHijacker()->GetProcessesInfo();
    if (procInfo.empty() || procInfo.size() <= 0) {
        printf("procInfo empty or size <= 0.\n");

        std::cin.get();
        return 0;
    }

    // PrintInfo
    for (const auto& processInfo : procInfo) {
        printf("%lu\t%s\t%s\n", processInfo.id, processInfo.name.c_str(), processInfo.path.c_str());
    }
    printf("\n");

    /* NtDll-Native */

    // Switch manager to NtDll
    hijackersManager_.SetHijacker(SWITCH_NTDLL);

    // Capture and retcode check
    capRetCode = hijackersManager_.Cap(NTDLL_QIPD, CAP_PROCESSES, NULL);
    if (!CAP_RETCODE_IS_SUCCESS(capRetCode)) {
        printf("%s. (%lu)\n", hijackersManager_.cap_retcode_to_str(capRetCode).c_str(), capRetCode);

        std::cin.get();
        return 0;
    }

    // PrintInfo
    for (const auto& processInfo : procInfo) {
        printf("%lu\t%s\t%s\n", processInfo.id, processInfo.name.c_str(), processInfo.path.c_str());
    }
    printf("\n");

    /* Direct SysCall */

    // Switch manager to SysCall
    hijackersManager_.SetHijacker(SWITCH_SYSCALL);

    // Capture and retcode check
    capRetCode = hijackersManager_.Cap(SYSCALL_QIPD, CAP_PROCESSES, NULL);
    if (!CAP_RETCODE_IS_SUCCESS(capRetCode)) {
        printf("%s. (%lu)\n", hijackersManager_.cap_retcode_to_str(capRetCode).c_str(), capRetCode);

        std::cin.get();
        return 0;
    }

    // PrintInfo
    for (const auto& processInfo : procInfo) {
        printf("%lu\t%s\t%s\n", processInfo.id, processInfo.name.c_str(), processInfo.path.c_str());
    }
    printf("\n");

    std::cin.get();
    return 0;
}