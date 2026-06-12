# 🛠 **Open-Source** SystemInformer
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-blue.svg)]()
[![Status: In Development](https://img.shields.io/badge/Status-In%20Development-orange.svg)]()
[![Open Source Love](https://badges.frapsoft.com/os/v1/open-source.svg?v=103)](https://github.com/ellerbrock/open-source-badges/)
[![Made with C++](https://img.shields.io/badge/Made%20with-C%2B%2B-00599C?style=flat-square&logo=c%2B%2B&logoColor=white)]()

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&pause=1000&color=00BFFF&center=true&vCenter=true&width=435&lines=%F0%9F%94%8D+SystemInformer;Windows+Internals+Research;WinAPI+%E2%86%92+NtDLL+%E2%86%92+SysCall" alt="Typing SVG" />
</p>

## 📑 Содержание
- [🤔 Цель форка?](#-цель-форка)
- [🔧 Что внутри?](#-что-внутри)
- [⚙️ Методы вызовов](#-методы-вызовов)
- [🛡️ Обход защит](#-обход-защит)
- [🤓 Примеры](#-примеры)
- [📞 Дисклеймер](#-дисклеймер)

## 🤔 Цель форка?
**SystemInformer** — это **OpenSource** исследовательский проект, демонстрирующий различные уровни взаимодействия с операционной системой Windows. Проект показывает эволюцию системных вызовов: от высокоуровневых API до syscall-инструкций.
### 🤔 Для чего нужен?
  - Для обход систем защит - **EDR**, **XDR**, **CobaltStrike** и других.
  - Повышение стабильности проектов которые работают уровнем выше **NtDLL-Native**.
  - Эксперементов с **Kernel-Exploitation**, **BSOD\Hardware Failure**, **BIOS\UEFI ToolKit**.
### 🤔 Чем полезен?
  - Имеет внутри себя динамический поиск системных номеров **SSN(SCN)**.
  - Содержит примеры использования каждого уровня привилегий **WINAPI**, **NtDll-Native**, **Direct SysCall**.
### 🎯 Цели проекта
  - Демонстрация работы с **user-mode, ntdll, syscall API** (высокоуровневые и низкоуровневые функции Windows)
  - Поддерживаемость и расширяемость других проектов с использованием уровня привилегий выше **NtDll-Native**.
  - Планируется добавление **непрямых системных вызовов(indirect syscalls)**, **непрямых переходов стека(gadjets)**.

## 🔧 Что внутри?
### 🔧 Текущий функционал
- 📋 **Снапшот процессов и их данных** через **user-mode API**, **NtDll нативные вызовы**, **Direct SysCall вызовы**.
- 🔍 **Динамический подбор SSN(SCN)** через **NtDll file parse** в функции `bool GetSCN(std::string ntdllFuncName, unsigned long& SCN);`.
- 🧬 **Доступ к NtDll-Native функциям** напрямую.
- ⚡ **Прямые системные вызовы(Direct SysCall)** через **NtDll file parse**.

## ⚙️ Методы вызовов
### Независимые
| Уровень | Метод | Файл\Функция |
|---------|-------|--------------|
| **🟢 User-mode** | Стандартные Windows API | `CreateToolhelp32Snapshot`, `EnumProcessModules` и другие |
| **🟡 NtDLL Native** | Нативные вызовы через ntdll.dll | `NtQuerySystemInformation` и другие |
| **🔴 Direct SysCall** | Прямые системные вызовы в обход **NtDll** | Собственный ассемблерный код SysCall заточенный под **x64** систему |

### 🚧 В разработке
- 😎 **Indirect syscalls** (функция `GetGJT`).
- 🛠 Дополнительные методы обхода защитных механизмов **EDR**, **XDR** и других.
- 🔬 Расширенная документация по каждому методу.

## 🛡️ Обход защит
| Метод | EDR (user-mode hook) | EDR (kernel callback) | XDR |
|-------|:---:|:---:|:---:|
| 🟢 User-mode API | ❌ | ❌ | ❌ |
| 🟡 NtDll Native | ⚠️ | ❌ | ❌ |
| 🔴 Direct SysCall | ✅ | ⚠️ | ✅ |
| 😎 Indirect SysCall | ✅ | ✅ | ✅ |

## ⚙️ Примеры
Проект изолированно гибкий и позволяет точечно взаимодействовать с каждым методом вплоть до asm-инструкций. Это сделано ради жертвы производительности для цены качества исследователя, а также совместимости.

Примеры можно найти в **`main.cpp`**:
```cpp
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
```

## 📞 Дисклеймер
**Этот проект создан исключительно в образовательных, исследовательских и тестовых целях.**\
**Запрещено:**
  1. **Использовать против юридических проектов.**
  2. **Применять или обходить против юридических системных защит.**

**Ты соглашаешься с тем, что:**
  1. **Автор форка не несёт ответственности за использование данного кода против любых юридических защит и систем безопасности применённые к тебе или третьим лицам.**
  2. **Вся ответственность за использование этого ПО лежит исключительно на тебе.**
  3. **Ты используешь этот код на свой страх и риск.**
