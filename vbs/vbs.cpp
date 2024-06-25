// Sample code to play with Virtualization Based Security features
// Reversed and written by mkedzier@redhat.com in 2020
//
// The code dumps information about VBS features.
// It was reverse engineered from some of the system components:
//  SecurityHealth.exe, VbsApi.dll and Win32_DeviceGuard.
// The purpose is for quick detection of available/enabled security
// features, not only related to VBS
//

#include "pch.h"
#include <iostream>
#include "windows.h"
#include "winternl.h"
#include "winbio.h"

#pragma comment(lib, "ntdll.lib")

typedef void (*VbsGetIssuesPtr)(DWORD *IssuesFlags);
typedef unsigned char (*VbsIsCapablePtr)(DWORD IssuesFlags);
typedef unsigned int(*HvciIsActivePtr)();
typedef unsigned int(*HvciIncompatibilityScanInitializePtr)(void *CallBackFunction, void *Ar1, void *Arg2);
typedef unsigned int(*HvciIncompatibilityScanStartPtr)(PVOID Context);
typedef unsigned int(*HvciIncompatibilityScanGetResultPtr)(PVOID Context);
typedef int (*NgcIsAnyContainerInVsmPtr)(unsigned int *Value);


#define SystemIsolatedUserModeInformation 0xA5
#define SystemBootEnvironmentInformation 0x5A

// This structure is not documented
#define SystemDmaProtectionInformation 0xA9
typedef struct _VSM_PROTECTION_INFO
{
	UCHAR dmaProtection;
	UCHAR dmaProtection2; // it looks to be a copy of dmaProtection?
	UCHAR ModeBasedExecControl;
	UCHAR ApicVirtualization;
} VSM_PROTECTION_INFO;

// This call in not documented but trace leads to 
// nt!HvlQueryVsmProtectionInfo
// It displays information related to DMA protection, \
// information if MBEC and Apic Virtualizaton is enabled. 
unsigned int DisplaySystemDmaProtectionInformation()
{
	ULONG retLen = 0;
	VSM_PROTECTION_INFO protectionFlags = { 0 };

	SYSTEM_INFORMATION_CLASS infoClass = (SYSTEM_INFORMATION_CLASS)SystemDmaProtectionInformation;

	NTSTATUS status = NtQuerySystemInformation(infoClass, &protectionFlags, 4, &retLen);
	if (status < 0)
		return 0;
	if (retLen != 4)
		return 0;

	printf("%s Flags [0x%08x] \n", __FUNCTION__, *(unsigned int*)&protectionFlags);
	printf("DMA protection available [%s]\n", protectionFlags.dmaProtection == 1 ? "YES" : "NO");
	printf("DMA protection# available [%s]\n", protectionFlags.dmaProtection2 == 1 ? "YES" : "NO");
	printf("Mode Based Execution Control [%s]\n", protectionFlags.ModeBasedExecControl == 1 ? "ON" : "OFF");
	printf("Apic Virtualization [%s]\n", protectionFlags.ApicVirtualization == 1 ? "ON" : "OFF");

	return 0;
}

#define SystemDmaGuardPolicyInformation 0xCA
// This is also not documented. It is related to "Kernel DMA Protection" feature
// described here: 
// https://docs.microsoft.com/en-us/windows/security/information-protection/kernel-dma-protection-for-thunderbolt
//
bool GetSystemDmaGuardPolicyInformation()
{
	ULONG retLen = 0;
	BYTE isDmaGuardEnabled = 0;
	SYSTEM_INFORMATION_CLASS infoClass = (SYSTEM_INFORMATION_CLASS)SystemDmaGuardPolicyInformation;

	NTSTATUS status = NtQuerySystemInformation(infoClass, &isDmaGuardEnabled, 1, &retLen);
	if (status < 0)
		return false;
	if (retLen != 1)
		return false;

	printf("DmaGuardProtection running [%x] \n", isDmaGuardEnabled);
	return (isDmaGuardEnabled == 1);
}

// This check is related to PPAM - Platform Properties Assessment Module from Intel?
bool IsPPamEnabled()
{
	ULONG retLen = 0;
	BYTE info[32] = { 0 };

	SYSTEM_INFORMATION_CLASS infoClass = (SYSTEM_INFORMATION_CLASS)SystemBootEnvironmentInformation;

	NTSTATUS status = NtQuerySystemInformation(infoClass, info, 32, &retLen);
	if (status < 0)
		return false;
	if (retLen != 32)
		return false;

	// Check if PPAM is enabled in BootFlags
	unsigned __int64 flags = *(unsigned __int64*)&info[24];
	bool isPPAMenabled = ((flags >> 7) & 0x7F) == 10;

	printf("PPAM enabled [%d] \n", isPPAMenabled);
	return isPPAMenabled;
}

// Any hints what DGR?
bool IsDgrEnabled()
{
	ULONG retLen = 0;
	BYTE info[32] = { 0 };

	SYSTEM_INFORMATION_CLASS infoClass = (SYSTEM_INFORMATION_CLASS)SystemBootEnvironmentInformation;

	NTSTATUS status = NtQuerySystemInformation(infoClass, info, 32, &retLen);
	if (status < 0)
		return false;
	if (retLen != 32)
		return false;

	// Check if Dgr (whatever it is) is enabled in BootFlags
	unsigned __int64 flags = *(unsigned __int64*)&info[24];
	bool isDgr = ((flags >> 7) & 0x7F) == 20;

	printf("Dgr enabled [%d] \n", isDgr);
	return isDgr;
}

unsigned int GetFirmwareTypeFromBootEnvironment()
{
	ULONG retLen = 0;
	BYTE info[32] = { 0 };
	FIRMWARE_TYPE fwType = FirmwareTypeUnknown;

	const char *FirmwareTypeUnknownStr = "FirmwareTypeUnknown";
	const char *FirmwareTypeBiosStr = "FirmwareTypeBios";
	const char *FirmwareTypeUefiStr = "FirmwareTypeUefi";

	SYSTEM_INFORMATION_CLASS infoClass = (SYSTEM_INFORMATION_CLASS)SystemBootEnvironmentInformation;

	NTSTATUS status = NtQuerySystemInformation(infoClass, info, 32, &retLen);
	if (status < 0)
		return 0;
	if (retLen != 32)
		return 0;

	const char *fwStr = NULL;
	fwType = (FIRMWARE_TYPE)*(DWORD*)&info[16];
	switch (fwType)
	{
	case FirmwareTypeUnknown:
		fwStr = FirmwareTypeUnknownStr;
		break;
	case FirmwareTypeBios:
		fwStr = FirmwareTypeBiosStr;
		break;
	case FirmwareTypeUefi:
		fwStr = FirmwareTypeUefiStr;
		break;		
	}

	printf("firmware type [%s] \n", fwStr);
	return fwType;
}

// Check related to secure biotmetrics feature.
bool IsSecureFingerprintAvailable()
{
	HRESULT hr = S_OK;
	PWINBIO_UNIT_SCHEMA unitSchema = NULL;
	SIZE_T unitCount = 0;
	SIZE_T index = 0;

	hr = WinBioEnumBiometricUnits(
		WINBIO_TYPE_FINGERPRINT,
		&unitSchema,
		&unitCount);

	if (FAILED(hr))
	{
		return false;
	}

	return (unitCount != 0);
}

// Detects if Biometrics related to face features are enabled
bool IsSecureFaceAvailable()
{
	HRESULT hr = S_OK;
	PWINBIO_UNIT_SCHEMA unitSchema = NULL;
	SIZE_T unitCount = 0;
	SIZE_T index = 0;

	hr = WinBioEnumBiometricUnits(
		WINBIO_TYPE_FACIAL_FEATURES,      
		&unitSchema,
		&unitCount);

	if (FAILED(hr))
	{
		return false;
	}	
	
	return (unitCount != 0);
}

// Dumps information about status of Code Integrity features.
// It can be used to check if VSM (Virtual Secure Mode) and HVCI
// are anabled and what is their state (audit).
// CODEINTEGRITY_OPTION_UMCI_ENABLED - VSM is enabled
// CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED when HVCI feature is enabled
// CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED when HVCI feature is enabled
void DisplayCodeIntegrityInformation()
{
	printf("CodeIntegrityInformation:\n");
	ULONG retLen = 0;
	SYSTEM_CODEINTEGRITY_INFORMATION codeIntegrityInfo = { 0 };
	ULONG reqLen = sizeof(codeIntegrityInfo);
	codeIntegrityInfo.Length = reqLen;

	NTSTATUS status = NtQuerySystemInformation(SystemCodeIntegrityInformation, 
		&codeIntegrityInfo, 
		reqLen, 
		&retLen);

	if (status < 0)
		return;
	if (reqLen != sizeof(codeIntegrityInfo))
		return;

	ULONG options = codeIntegrityInfo.CodeIntegrityOptions;

	if (options & CODEINTEGRITY_OPTION_ENABLED)
	{
		printf(" CODEINTEGRITY_OPTION_ENABLED\n");
	}
	if (options & CODEINTEGRITY_OPTION_TESTSIGN)
	{
		printf(" CODEINTEGRITY_OPTION_TESTSIGN\n");
	}
	if (options & CODEINTEGRITY_OPTION_UMCI_ENABLED)
	{
		printf(" CODEINTEGRITY_OPTION_UMCI_ENABLED\n");
	}
	if (options & CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED)
	{
		printf(" CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED\n");
	}
	if (options & CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED)
	{
		printf(" CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED\n");
	}
	if (options & CODEINTEGRITY_OPTION_TEST_BUILD)
	{
		printf(" CODEINTEGRITY_OPTION_TEST_BUILD\n");
	}
	if (options & CODEINTEGRITY_OPTION_PREPRODUCTION_BUILD)
	{
		printf(" CODEINTEGRITY_OPTION_PREPRODUCTION_BUILD\n");
	}
	if (options & CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED)
	{
		printf(" CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED\n");
	}
	if (options & CODEINTEGRITY_OPTION_FLIGHT_BUILD)
	{
		printf(" CODEINTEGRITY_OPTION_FLIGHT_BUILD\n");
	}
	if (options & CODEINTEGRITY_OPTION_FLIGHTING_ENABLED)
	{
		printf(" CODEINTEGRITY_OPTION_FLIGHTING_ENABLED\n");
	}
	if (options & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED)
	{
		printf(" CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED\n");
	}
	if (options & CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED)
	{
		printf(" CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED\n");
	}
	if (options & CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED)
	{
		printf(" CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED\n");
	}
	if (options & CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED)
	{
		printf(" CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED\n");
	}	
}

// Taken from SMM specification
#define FIXED_COMM_BUFFERS					1
#define COMM_BUFFERS_NESTED_PTR_PROTECTION	2
#define SYSTEM_RESOURCE_PROTECTION			4

#pragma pack(push, 1)

typedef struct _SMM_SECURITY_TABLE
{
	UINT signature;
	UINT length;
	BYTE revision;
	BYTE checksum;
	BYTE OEMID[6];
	BYTE OEMTablelID[8];
	DWORD OEMRevision;
	DWORD CreatorId;
	DWORD CreateRevision;
	DWORD ProtectionFlags;

} SMM_SECURITY_TABLE;

#pragma pack(pop)

bool CheckIfSRATexists()
{
	BYTE fwTableBuffer[40] = { 0x0 };

	UINT len = GetSystemFirmwareTable(
		'ACPI',
		'TARS',
		NULL,
		0);

	printf("Size of SRAT table: [%d] \n",
		len);

	return false;
}

// Checks SMM Security Mitigation Table (WSMT)
// This is based on MS code from VbsApi and it is wrong.
// They should check bit fields at offset 36 (DWORD)
// not at offset 28
bool CheckWSMTProtection()
{	
	BYTE fwTableBuffer[40] = { 0x0 };

	UINT len = GetSystemFirmwareTable(
		'ACPI',
		'TMSW', //WSMT
		fwTableBuffer,
		sizeof(SMM_SECURITY_TABLE));

	if (len == sizeof(SMM_SECURITY_TABLE))
	{
		SMM_SECURITY_TABLE *table = (SMM_SECURITY_TABLE*)fwTableBuffer;

		// MS code checks bit fields at offset 28 (Creator ID?)
		if (!(fwTableBuffer[0x1C] & FIXED_COMM_BUFFERS) ||
			!(fwTableBuffer[0x1C] & COMM_BUFFERS_NESTED_PTR_PROTECTION) ||
			!(fwTableBuffer[0x1C] & SYSTEM_RESOURCE_PROTECTION))
		{
			printf("Protection Flags were not found!\n");
			return false;
		}
		printf("Values found!\n");
		return true;
	}
	return false;
}

// Checks SMM Security Mitigation Table (WSMT).
// This is fixed and correct version -  Device Guard 
// has correct code. VbsApi does checking in incorrect way.
bool CheckWSMTProtectionFixed()
{
	SMM_SECURITY_TABLE fwTableBuffer = { 0x0 };

	UINT len = GetSystemFirmwareTable(
		'ACPI',
		'TMSW', //WSMT
		&fwTableBuffer,
		sizeof(SMM_SECURITY_TABLE));

	if (len == sizeof(SMM_SECURITY_TABLE))
	{
		if (!(fwTableBuffer.ProtectionFlags & FIXED_COMM_BUFFERS) ||
			!(fwTableBuffer.ProtectionFlags & COMM_BUFFERS_NESTED_PTR_PROTECTION) ||
			!(fwTableBuffer.ProtectionFlags & SYSTEM_RESOURCE_PROTECTION))
		{
			return false;
		}
		return true;
	}
	return false;
}


// Assembler code for checking if hypervisor is present
// - not used currently
extern "C"
{
	unsigned int HviIsAnyHypervisorPresent();
	unsigned char HviIsHypervisorMicrosoftCompatible();
	DWORD CpuidTest();
}

// This undocumented structure taken from 
// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/isolated_user_mode.htm
// Some notes are based on this description

#pragma pack(push, 1)
typedef struct _SYSTEM_ISOLATED_USER_MODE_INFORMATION
{
	struct _secureFlags
	{
		UCHAR SecureKernelRunning : 1;
		UCHAR HvciEnabled : 1;
		UCHAR HvciStrictMode : 1;
		UCHAR DebugEnabled : 1;
		UCHAR SpareFlags : 4;
	} secureFlags;
	
	struct _additionalFlags
	{
		UCHAR TrustletRunning : 1;
		UCHAR SpareFlags2 : 7;
	} additonalFlags;
	
	struct _spare0
	{
		UCHAR Spare0[6];
	} spare0;
		
	struct _spare1
	{
		ULONGLONG Spare1;
	} spare1;

} SYSTEM_ISOLATED_USER_MODE_INFORMATION;
#pragma pack(pop)

// Check if HVCI feature is active. 
// VbsApi.dll and extended
// This is exactly how Hvci detection is done
// Notes:
// if SecureKernel is running, it means that IUM initialization was 
// successfull; if UIM initilization was successfull it means that
// 'cpuid leaf 0x40000003 so that ebx on output has a set AccessVsm bit'
unsigned int HvciIsActive()
{	
	SYSTEM_ISOLATED_USER_MODE_INFORMATION information = {};
	ULONG retLen = 0;
	unsigned int ret = 0;

	// 0xA5 is undocumented SystemIsolatedUserModeInformation
	SYSTEM_INFORMATION_CLASS infoClass = (SYSTEM_INFORMATION_CLASS) 0xA5;

	NTSTATUS status = NtQuerySystemInformation(infoClass, &information, 16, &retLen);
	if (status < 0)
		return 0;
	if (retLen != 16)
		return 0;
#if 1
	printf("SecureKernelRunning [%s]\nHvciEnabled [%s]\nHvciStrictMode [%s]\nDebugEnabled [%s]\nSpareFlags [%s]\n",
		information.secureFlags.SecureKernelRunning ? "ON" : "OFF",
		information.secureFlags.HvciEnabled ? "ON" : "OFF",
		information.secureFlags.HvciStrictMode ? "ON" : "OFF",
		information.secureFlags.DebugEnabled? "ON" : "OFF",
		information.secureFlags.SpareFlags ? "ON" : "OFF");
	
	printf("TrustletRunning [%s] \n",
		information.additonalFlags.TrustletRunning ? "ON" : "OFF");

#endif

	ret = (information.secureFlags.HvciEnabled >> 1) & 1;
	printf("Hvcsi is [%s] \n", ret?"ON":"OFF");
	return ret;
}

// This call is related to checking Vsm availibility which in fact
// is related Trustlets 
// The code is in NgcIsAnyContainerInVsm
// Note: both functions IsVmsAvailable and IsVmsAvailable don't work
// correctly or they are used in different context
bool IsVsmAvailable()
{
	SYSTEM_ISOLATED_USER_MODE_INFORMATION information = {};

	ULONG retLen = 0;
	unsigned int ret = 0;

	SYSTEM_INFORMATION_CLASS infoClass = (SYSTEM_INFORMATION_CLASS)SystemIsolatedUserModeInformation;

	NTSTATUS status = NtQuerySystemInformation(infoClass, &information, 16, &retLen);
	if (status < 0)
		return 0;
	if (retLen != 16)
		return 0;

	if (information.secureFlags.SecureKernelRunning && information.additonalFlags.TrustletRunning)
	{
		printf("VSM is available\n");
		return true;
	}
	else
	{
		printf("VSM is NOT available!\n");
		return false;
	}	
}

extern "C" {
NTSTATUS
ZwQuerySystemInformationEx(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID InputBuffer,
	ULONG InputBufferLength,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	ULONG *ReturnLength);
}

bool IsVsmAvailableEx()
{
	ULONG retLen = 0;

	BYTE information[8] = {0};
	information[0] = 1;
	BYTE systemInformation[16] = { 0 };

	unsigned int ret = 0;

	SYSTEM_INFORMATION_CLASS infoClass = (SYSTEM_INFORMATION_CLASS)SystemIsolatedUserModeInformation;

	NTSTATUS status = ZwQuerySystemInformationEx(infoClass,
		&information,
		8,
		systemInformation,
		16,
		&retLen);

	if (status < 0)
		return 0;
	if (retLen != 16)
		return 0;

	if ((information[0] & 9) == 9)
	{
		printf("VSM is available\n");
		return true;
	}
	else
	{
		printf("VSM is NOT available!\n");
		return false;
	}
}


bool IsSecureBioEnabled()
{
	wchar_t windowsDir[512];
	wchar_t cryptngcFullPath[4096];
	UINT ret = GetWindowsDirectory(windowsDir, 512);
	if (!ret)
	{
		printf("Can't get Windows installation directory!\n");
		return false;
	}

	wsprintf(cryptngcFullPath, L"%ws\\system32\\cryptngc.dll", windowsDir);

	HINSTANCE cryptngc = LoadLibrary(cryptngcFullPath);
	if (!cryptngc)
	{
		printf("Can't load cryptngc.dll\n");
		return false;
	}

	NgcIsAnyContainerInVsmPtr NgcIsAnyContainerInVsmCall = (NgcIsAnyContainerInVsmPtr)GetProcAddress(cryptngc, "NgcIsAnyContainerInVsm");
	if (!NgcIsAnyContainerInVsmCall)
	{
		printf("Can't get address of NgcIsAnyContainerInVsmCall\n");
		FreeLibrary((HMODULE)cryptngc);
		return false;
	}

	unsigned int Value = 0;

	int result = NgcIsAnyContainerInVsmCall(&Value);
	if (result < 0)
	{
		printf("NgcIsAnyContainerInVsmCall returned error\n");
	}

	printf("number of containers?? [%d] \n", Value);
	FreeLibrary((HMODULE)cryptngc);
	return true;
}

#define VBS_ISSUES_FLAG_INCOMPATIBLE_PROCESSOR					 0x1
#define VBS_ISSUES_FLAG_INCOMPATIBLE_HV_OR_NO_SLAT				 0x2
#define VBS_ISSUES_FLAG_SECURE_BOOT_NOT_ENABLED					 0x4
#define VBS_ISSUES_FLAG_DMA_PROTECTION_NOT_AVAIL				 0x8
#define VBS_ISSUES_FLAG_MODE_EXECUTION_CONTROL_NOT_AVAIL		0x10
#define VBS_ISSUES_FLAG_FIRMWARE_NOT_UEFI						0x20
#define VBS_ISSUES_FLAG_DEBUGGER_ENABLED						0x40
#define VBS_ISSUES_FLAG_SMM_NO_WTSM_PROTECTION					0x80
#define VBS_ISSUES_FLAG_UEFI_HAS_NOT_MORLOCK				   0x100			
#define VBS_ISSUES_FLAG_NOT_ENOUGH_MEMORY					   0x200
#define VBS_ISSUES_FLAG_INCOMPATIBLE_HV_OR_NO_VIR_FW		   0x400
#define VBS_ISSUES_FLAG_APIC_VIRTUALIZATION_NOT_AVAIL		  0x1000			
#define VBS_ISSUES_FLAG_UKNOWN								   0x800	

void InterpretAndDisplayVbsIssuesFlags(DWORD Flags)
{
	if (Flags & VBS_ISSUES_FLAG_INCOMPATIBLE_PROCESSOR)
	{
		printf("--Incompatible system - wProcessorArchitecture 9 or 12 expected!\n");
	}

	if (Flags & VBS_ISSUES_FLAG_INCOMPATIBLE_HV_OR_NO_SLAT)
	{
		printf("--No Microsoft-compatible Hypervisor or no PF_SECOND_LEVEL_ADDRESS_TRANSLATION\n");
	}

	if (Flags & VBS_ISSUES_FLAG_INCOMPATIBLE_HV_OR_NO_VIR_FW)
	{
		printf("--No Microsoft-compatible Hypervisor or no PF_VIRT_FIRWARE_ENABLED\n");
	}
	
	if (Flags & VBS_ISSUES_FLAG_SECURE_BOOT_NOT_ENABLED)
	{
		printf("--Secure Boot is not enabled\n");
	}

	if (Flags & VBS_ISSUES_FLAG_DMA_PROTECTION_NOT_AVAIL)
	{
		printf("--Dma Protection is not available\n");
	}

	if (Flags & VBS_ISSUES_FLAG_MODE_EXECUTION_CONTROL_NOT_AVAIL)
	{
		printf("--Mode Execution Control is not available\n");
	}

	if (Flags & VBS_ISSUES_FLAG_APIC_VIRTUALIZATION_NOT_AVAIL)
	{
		printf("--APIC Virtualization is not available\n");
	}
	
	if (Flags & VBS_ISSUES_FLAG_FIRMWARE_NOT_UEFI)
	{
		printf("--UEFI firmware not available\n");
	}

	if (Flags & VBS_ISSUES_FLAG_NOT_ENOUGH_MEMORY)
	{
		printf("--Not enough physical memory\n");
	}

	if (Flags & VBS_ISSUES_FLAG_DEBUGGER_ENABLED)
	{
		printf("--Kernel debugger is enabled\n");
	}

#if 0
	// This function that is in VbsApi doesn't work correcty
	// - checks are done in wrong places
	if (Flags & VBS_ISSUES_FLAG_SMM_NO_WTSM_PROTECTION)
	{
		// Look at CheckWSMTProtection how this 
		// check is done
		printf("--Not supported Windows SMM Security Mitigation Protection\n");
	}
#endif

	if (!CheckWSMTProtectionFixed())
	{
		// Look at CheckWSMTProtection how this 
		// check is done
		printf("--Not supported Windows SMM Security Mitigation Protection\n");
	}

	if (Flags & VBS_ISSUES_FLAG_UEFI_HAS_NOT_MORLOCK)
	{
		printf("--NO MemoryOverwriteRequestControlLock UEFI variable found\n");
	}
}

void DriverScanCallback(__int64 a1, int a2, __int64 a3, int **a4)
{
	if (!a3)
	{
		printf("a3 error!\n");
	}
	else
	{
		printf("Scan callback: [%x] [%x] [%x] \n", a1, a2, a3);
	}
}

// Check if VT-d is enabled in the BIOS
bool CheckVT_D()
{
	SMM_SECURITY_TABLE fwTableBuffer = { 0x0 };

	UINT len = GetSystemFirmwareTable(
		'ACPI',
		'RAMD',
		NULL,
		0);

	printf("VT-D is [%s] \n", len ? "ON" : "OFF");

	if (len)
		return true;

	return false;
}

int main()
{
	CheckIfSRATexists();
	CheckVT_D();

	CheckWSMTProtectionFixed();
	IsDgrEnabled();
	IsVsmAvailableEx();
	IsSecureFaceAvailable();

	DisplaySystemDmaProtectionInformation();
	GetFirmwareTypeFromBootEnvironment();
	DisplayCodeIntegrityInformation();
	
	wchar_t windowsDir[512];
	wchar_t vbsApiFullPath[4096];
	UINT ret = GetWindowsDirectory(windowsDir, 512);
	if (!ret)
	{
		printf("Can't get Windows installation directory!\n");
		return 1;
	}

	wsprintf(vbsApiFullPath, L"%ws\\system32\\VbsApi.dll", windowsDir);

	// VbsApi exports several functions that are used by HealthService
	// to deal with Virtualization Based security features
	
	HINSTANCE vbsApi = LoadLibrary(vbsApiFullPath);
	if (!vbsApi)
	{
		printf("Can't load VbsApi.dll \n");
		return 1;
	}
	
	// GetIssues call returned detected issues for VBS.
	// Flags are documented 
	VbsGetIssuesPtr vbsGetIssuesCall = (VbsGetIssuesPtr) GetProcAddress(vbsApi, "VbsGetIssues");
	if (!vbsGetIssuesCall)
	{
		printf("Can't get address of VbsGetIssues \n");
		FreeLibrary((HMODULE)vbsApi);
		return 1;
	}

	VbsIsCapablePtr VbsIsCapableCall = (VbsIsCapablePtr)GetProcAddress(vbsApi, "VbsIsCapable");
	if (!VbsIsCapableCall)
	{
		printf("Can't get address of VbsIsCapable\n");
		FreeLibrary((HMODULE)vbsApi);
		return 1;
	}

	HvciIsActivePtr HvciIsActiveCall = (HvciIsActivePtr)GetProcAddress(vbsApi, "HvciIsActive");
	if (!VbsIsCapableCall)
	{
		printf("Can't get address of HvciIsActive \n");
		FreeLibrary((HMODULE)vbsApi);
		return 1;
	}

	HvciIncompatibilityScanInitializePtr HvciIncompatibilityScanInitializeCall = (HvciIncompatibilityScanInitializePtr)GetProcAddress(vbsApi, "HvciIncompatibilityScanInitialize");
	if (!HvciIncompatibilityScanInitializeCall)
	{
		printf("Can't get address of HvciIncompatibilityScanInitializeCall \n");
		FreeLibrary((HMODULE)vbsApi);
		return 1;
	}

	HvciIncompatibilityScanStartPtr HvciIncompatibilityScanStartCall = (HvciIncompatibilityScanStartPtr)GetProcAddress(vbsApi, "HvciIncompatibilityScanStart");
	if (!HvciIncompatibilityScanStartCall)
	{
		printf("Can't get address of HvciIncompatibilityScanStartCall \n");
		FreeLibrary((HMODULE)vbsApi);
		return 1;
	}

	HvciIncompatibilityScanGetResultPtr HvciIncompatibilityScanGetResultCall = (HvciIncompatibilityScanGetResultPtr)GetProcAddress(vbsApi, "HvciIncompatibilityScanGetResult");
	if (!HvciIncompatibilityScanGetResultCall)
	{
		printf("Can't get address of HvciIncompatibilityScanGetResultCall \n");
		FreeLibrary((HMODULE)vbsApi);
		return 1;
	}

#if 0
	DWORD context[4] = { 1, 2, 3, 4 };

	typedef struct _aa
	{
		void *a0;
		void *a1;
		void *a2;
		void *a3;
		void *callBack;
		void *context;
		void *a6;
		void *a7;
	} aa;


	typedef struct hvciIncompatibilityScanStartArgs
	{
		HANDLE mutex;
		HANDLE thread;
		DWORD value;
		DWORD status;
		HANDLE database;
		void *a4;
		void *a5;
		void *a6;
		void *a7;
	} hvciIncompatibilityScanStartArgs;

	hvciIncompatibilityScanStartArgs startArg;
	startArg.mutex = (HANDLE)0x0;
	startArg.thread = (HANDLE)0x0;
	startArg.value = 0;
	startArg.status = 0;
	startArg.database = (HANDLE)0x0;
	startArg.a4 = DriverScanCallback;
	startArg.a5 = (void*)0x0;
	startArg.a6 = (void*)0x0;
	startArg.a7 = (void*)0x0;

	aa *BlockAddress = NULL;
	
	HvciIncompatibilityScanInitializeCall(DriverScanCallback, context, &BlockAddress);

	printf("callback [%p] \n", BlockAddress->callBack);
	printf("callback [%p] \n", BlockAddress->context);

	// After this call, fields Mutex, Handle and thread should be filled.
	HvciIncompatibilityScanStartCall(&startArg);

	DWORD scanResult = HvciIncompatibilityScanGetResultCall(&startArg);
	printf("Scan result [%d] \n", scanResult);

	printf("a0 [%p] \n", BlockAddress->a0);
	printf("a1 [%p] \n", BlockAddress->a1);
	printf("a2 [%p] \n", BlockAddress->a2);
	printf("a3 [%p] \n", BlockAddress->a3);
	printf("a6 [%p] \n", BlockAddress->a6);
	printf("a7 [%p] \n", BlockAddress->a7);
	printf("\n");
	printf("mutex [%p] \n", startArg.mutex); 
	printf("thread [%p] \n", startArg.thread);
	printf("status [%x] \n", startArg.status);
	printf("value [%x] \n", startArg.value);
	printf("database [%p] \n", startArg.database);
	printf("a4 [%p] \n", startArg.a4);
	printf("a5 [%p] \n", startArg.a5);
	printf("a6 [%p] \n", startArg.a6);
	printf("a7 [%p] \n", startArg.a7);
#endif
	GetSystemDmaGuardPolicyInformation();

	printf("Getting VBS issues...\n");

	DWORD vbsIssues = 0;
	vbsGetIssuesCall(&vbsIssues);
	printf("issues flags [0x%08x]\n", vbsIssues);
	InterpretAndDisplayVbsIssuesFlags(vbsIssues);

	// VbsIsCapable call checks if at least one issue was found:
	// bits are set:VBS_ISSUES_FLAG_INCOMPATIBLE_PROCES | 
	//				VBS_ISSUES_FLAG_INCOMPATIBLE_HV_OR_NO_SLAT |
	//				VBS_ISSUES_FLAG_INCOMPATIBLE_HV_OR_NO_VIR_FW |
	//				VBS_ISSUES_FLAG_UKNOWN
	//
	// If at least one of those issues was found it means that VBS is NOT supported
	//
	// Note: VBS_ISSUES_FLAG_UKNOWN is uknown as it is not not set by 
	// VbsGetIssues call.

	BYTE isVBSCapable = VbsIsCapableCall(vbsIssues);
	printf(" System VBS capable [%s] \n", isVBSCapable ? "YES" : "NO");

	printf(" HVCI is [%s] \n", HvciIsActiveCall() ? "ACTIVE" : "INACTIVE");
	
	if (HviIsAnyHypervisorPresent())
	{
		if (HviIsHypervisorMicrosoftCompatible())
		{
			printf("MS compatible hypervisor found! \n");
		}		
	}

	FreeLibrary((HMODULE)vbsApi);
	return 0;
}
