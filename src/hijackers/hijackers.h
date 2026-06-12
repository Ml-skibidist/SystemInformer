/* hijackers.h - WINAPI/NtDll/Syscalls. */

#ifndef HIJACKERS_H
#define HIJACKERS_H

// File code includes
#include <string>
#include <vector>
#include <memory>

// Info
struct ProcessInfo
{
	std::string name;			// name of bin
	std::string path;			// path of bin

	unsigned long id;			// id of bin
};
struct ModuleInfo
{
	std::string name;			// name of bin
	std::string path;			// path of bin
};
struct ThreadInfo
{
	unsigned long ownerId;		// bin id of thread
};

// Switches
enum SwitchesEnum : unsigned char
{
	Switch_WinAPI,		// WinAPI (CTH32S, K32E)
	Switch_NtDll,		// NtDll (QIPB, QIPD)
	Switch_SysCall,		// Syscall (QIPB, QIPD)
};
// Captures
enum CapsEnum : unsigned char
{
	Cap_Processes = (1 << 0),		// Bins
	Cap_Modules = (1 << 1),			// Libs
	Cap_Threads = (1 << 2),			// Threads
};
// Return codes
enum CapRetCodesEnum : unsigned char
{
	Cap_RetCode_Successfully = (1 << 0),			// No error
	Cap_RetCode_UnSupported = (1 << 1),				// Unsupported method and cap
	Cap_RetCode_BadArgs = (1 << 2),					// Bad args, can be invalid process id
	Cap_RetCode_Failed_SetMethod = (1 << 3),		// Bad method, can be invalid method of hijacker
	Cap_RetCode_Failed_CapProcesses = (1 << 4),		// Fail in method of list bins
	Cap_RetCode_Failed_CapModules = (1 << 5),		// Fail in method of list libs
	Cap_RetCode_Failed_CapThreads = (1 << 6),		// Fail in method of list threads
};
// WinAPI methods
enum WinAPIMethodsEnum : unsigned char
{
	WinAPI_CreateToolHelp32Snapshot,		// WinAPI CTH32S
	WinAPI_K32Enum,							// WinAPI K32E
	WinAPI_K32EnumEx,						// WinAPI K32EE
};
// NtDll methods
enum NtDllMethodsEnum : unsigned char
{
	NtDll_QueryInformationProcessDefault,		// NtDll QIPD
	NtDll_QueryInformationProcessBasic,			// NtDll QIPB
};
// Syscall methods
enum SysCallMethodsEnum : unsigned char
{
	SysCall_QueryInformationProcessDefault,		// SysCall QIPD
	SysCall_QueryInformationProcessBasic,		// SysCall QIPB
};

// Switches
#define SWITCH_WINAPI SwitchesEnum::Switch_WinAPI		// Switch to WinAPI (CTH32S, K32E)
#define SWITCH_NTDLL SwitchesEnum::Switch_NtDll			// Switch to NtDll (QIPD, QIPB)
#define SWITCH_SYSCALL SwitchesEnum::Switch_SysCall		// Switch to syscall (QIPD, QIPB)
// Captures
#define CAP_PROCESSES CapsEnum::Cap_Processes			// List of bins
#define CAP_MODULES CapsEnum::Cap_Modules				// List of libs
#define CAP_THREADS CapsEnum::Cap_Threads				// List of threads
// Cap return codes
#define CAP_RETCODE_SUCCESS CapRetCodesEnum::Cap_RetCode_Successfully							// No error
#define CAP_RETCODE_UNSUPPORTED CapRetCodesEnum::Cap_RetCode_UnSupported						// Unsupported method and cap
#define CAP_RETCODE_BAD_ARGS CapRetCodesEnum::Cap_RetCode_BadArgs								// Bad args, can be invalid process id
#define CAP_RETCODE_FAILED_SET_METHOD CapRetCodesEnum::Cap_RetCode_Failed_SetMethod				// Bad method, can be invalid method of hijacker
#define CAP_RETCODE_FAILED_CAP_PROCESSES CapRetCodesEnum::Cap_RetCode_Failed_CapProcesses		// Fail in method of list bins
#define CAP_RETCODE_FAILED_CAP_MODULES CapRetCodesEnum::Cap_RetCode_Failed_CapModules			// Fail in method of list libs
#define CAP_RETCODE_FAILED_CAP_THREADS CapRetCodesEnum::Cap_RetCode_Failed_CapThreads			// Fail in method of list threads
#define CAP_RETCODE_IS_SUCCESS(Status) (((CapRetCodesEnum)(Status)) == CAP_RETCODE_SUCCESS)		// Status checker
// WinAPI methods
#define WINAPI_CTH32S WinAPIMethodsEnum::WinAPI_CreateToolHelp32Snapshot		// WinAPI CTH32S
#define WINAPI_K32E WinAPIMethodsEnum::WinAPI_K32Enum							// WinAPI K32E
#define WINAPI_K32EE WinAPIMethodsEnum::WinAPI_K32EnumEx						// WinAPI K32EE
// NtDll methods	
#define NTDLL_QIPD NtDllMethodsEnum::NtDll_QueryInformationProcessDefault		// NtDll QIPD
#define NTDLL_QIPB NtDllMethodsEnum::NtDll_QueryInformationProcessBasic			// NtDll QIPB
// Syscall methods
#define SYSCALL_QIPD SysCallMethodsEnum::SysCall_QueryInformationProcessDefault		// Syscall QIPD
#define SYSCALL_QIPB SysCallMethodsEnum::SysCall_QueryInformationProcessBasic		// Syscall QIPB

// Interface
class IHijackers
{
protected:
	// Information
	std::vector<ProcessInfo> procInfoVec_;
	std::vector<ModuleInfo> modInfoVec_;
	std::vector<ThreadInfo> thInfoVec_;
	
	// Current method
	unsigned char method_;

public:
	// Constructor/Destructor
	IHijackers() = default;
	virtual ~IHijackers() = default;

	// Getters
	std::vector<ProcessInfo>& GetProcessesInfo() {
		return procInfoVec_;
	}
	std::vector<ModuleInfo>& GetModulesInfo() {
		return modInfoVec_;
	}
	std::vector<ThreadInfo>& GetThreadsInfo() {
		return thInfoVec_;
	}

	// Global methods
	virtual void SetMethod(unsigned char method) {
		method_ = method;
	}

	virtual bool CapProcesses() = 0;
	virtual bool CapModules(unsigned long procId) = 0;
	virtual bool CapThreads(unsigned long procId) = 0;
};

// WinAPI
class WinAPIHijacker : public IHijackers
{
private:
	// CTH32S type
	bool CreateToolHelp32SnapshotProcesses();
	bool CreateToolHelp32SnapshotModules(unsigned long procId);
	bool CreateToolHelp32SnapshotThreads(unsigned long procId);

	// K32E type
	bool K32EnumProcesses();
	bool K32EnumProcessModules(unsigned long procId);
	bool K32EnumProcessModulesEx(unsigned long procId);

public:
	WinAPIHijacker() = default;
	virtual ~WinAPIHijacker() override = default;

	// Overrided global methods
	virtual bool CapProcesses() override;
	virtual bool CapModules(unsigned long procId) override;
	virtual bool CapThreads(unsigned long procId) override;
};
// NtDll
class NtDllHijacker : public IHijackers
{
private:
	// QPID type
	bool QueryInformationProcessDefaultProcesses();
	bool QueryInformationProcessDefaultThreads(unsigned long procId);

	// QPIB type
	bool QueryInformationProcessBasicProcesses();

public:
	NtDllHijacker() = default;
	virtual ~NtDllHijacker() override = default;

	// Overrided global methods
	virtual bool CapProcesses() override;
	virtual bool CapModules(unsigned long procId) override;
	virtual bool CapThreads(unsigned long procId) override;
};
// Syscall
class SysCallHijacker : public IHijackers
{
private:
	// Find system service number(system call number)
	bool GetSCN(std::string ntdllFuncName, unsigned long& SCN);
	// Find gadjet(jmp, call, e.t.c)
	bool GetGJT(std::string ntdllFuncName, unsigned long& GJT);

	// QPID type
	bool QueryInformationProcessDefaultProcesses();
	bool QueryInformationProcessDefaultThreads(unsigned long procId);

	// QPIB type
	bool QueryInformationProcessBasicProcesses();

public:
	SysCallHijacker() = default;
	virtual ~SysCallHijacker() override = default;

	// Overrided global methods
	virtual bool CapProcesses() override;
	virtual bool CapModules(unsigned long procId) override;
	virtual bool CapThreads(unsigned long procId) override;
};

// Manager
class ManagerHijackers
{
private:
	// Interface
	std::unique_ptr<IHijackers> ihijacker_;

public:
	explicit ManagerHijackers(std::unique_ptr<IHijackers> ihijacker) : ihijacker_(std::move(ihijacker)) {}
	~ManagerHijackers() = default;

	// Getter/Setter
	IHijackers* GetHijacker();
	void SetHijacker(SwitchesEnum switcher);

	// Capturing
	CapRetCodesEnum Cap(unsigned char method, CapsEnum type, unsigned long procId);

	// Cap retcode converter
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
};

#endif // HIJACKERS_H