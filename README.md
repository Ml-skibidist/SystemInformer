# SystemInformer 🔍

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-blue.svg)]()
[![Status: In Development](https://img.shields.io/badge/Status-In%20Development-orange.svg)]()

## 📖 О проекте
**SystemInformer** — это исследовательский проект, демонстрирующий различные уровни взаимодействия с операционной системой Windows. Проект показывает эволюцию системных вызовов: от высокоуровневых API до прямых syscall-инструкций.

### 🎯 Цели проекта
- Демонстрация работы с **user-mode API** (высокоуровневые функции Windows)
- Переход на уровень **NtDLL** (нативные API функции)
- Реализация **прямых системных вызовов** (direct syscalls)
- Планируется добавление **непрямых системных вызовов** (indirect syscalls)

## 🔧 Текущий функционал
- 📋 **Снапшот процессов и их данных** через **user-mode API**, **NtDll нативные вызовы**, **Direct SysCall вызовы**.
- 🔍 **Динамический подбор SSN(SCN)** через **NtDll file parse**.
- 🧬 **Доступ к NtDLL нативным функциям** напрямую.
- ⚡ **Прямые системные вызовы Direct SysCall** через **NtDll SSN(SCN) parse**.

### 🚧 В разработке
- 🌐 **Indirect syscalls** (функция `GetGJT`).
- Дополнительные методы обхода защитных механизмов **EDR**, **XDR** и других.
- Расширенная документация по каждому методу.

## 🧠 Как это работает
Проект демонстрирует три уровня взаимодействия с ядром Windows:
| Уровень | Метод | Файл/Функция |
|---------|-------|---------------|
| **🟢 User-mode** | Стандартные Windows API | `CreateToolhelp32Snapshot`, `EnumProcessModules` и другие |
| **🟡 NtDLL Native** | Нативные вызовы через ntdll.dll | `NtQuerySystemInformation` и другие |
| **🔴 Direct SysCall** | Прямые системные вызовы в обход **NtDll** | Собственный ассемблерный код SysCall заточенный под **x64** систему |

### 🔑 Ключевая особенность: динамический парсинг SSN(SCN)
Вместо хардкодных номеров системных сервисов **SSN(SCN)**, проект парсит `ntdll.dll` напрямую с диска и извлекает **SSN(SCN)** динамически. Это делает вызовы более устойчивыми к изменениям между версиями Windows ядра.
