/* EntryPoint of this file - main.cpp. */

#include <iostream>

#include "src/hijackers/hijackers.h"
#include "src/utils/convert.h"

int main()
{
    ManagerHijackers hijackersManager_{ std::make_unique<SysCallHijacker>() };

    unsigned char capRetCode = hijackersManager_.Cap(SYSCALL_QIPD, CAP_PROCESSES, NULL);
    if (!CAP_RETCODE_IS_SUCCESS(capRetCode)) {
        printf("%s. (%lu)\n", UtilsConvert::cap_retcode_to_str(capRetCode).c_str(), capRetCode);

        std::cin.get();
        return 0;
    }

    std::vector<ProcessInfo> procInfo = hijackersManager_.GetHijacker()->GetProcessesInfo();
    if (procInfo.empty() || procInfo.size() <= 0) {
        printf("procInfo empty or size <= 0.\n");

        std::cin.get();
        return 0;
    }

    for (const auto& processInfo : procInfo) {
        printf("%lu\t%s\t%s\n", processInfo.id, processInfo.name.c_str(), processInfo.path.c_str());
    }
    printf("\n");



    std::cin.get();
    return 0;
}