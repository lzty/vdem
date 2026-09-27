# C++ prototype code for process trait implementions
```c++
#include <ntifs.h>

using FnPsLookupProcessByProcessId = NTSTATUS(*)(HANDLE, PEPROCESS*);
using FnMmMapLockedPagesSpecifyCache = PVOID(*)(PMDL MemoryDescriptorList,
	KPROCESSOR_MODE AccessMode,
	MEMORY_CACHING_TYPE CacheType,
	PVOID RequestedAddress,
	ULONG BugCheckOnFailure,
	ULONG Priority);
using FnPsSuspendProcess = NTSTATUS(*)(PEPROCESS);
using FnObDereferenceObject = void(*)(PVOID);
using FnZwOpenProcess = NTSTATUS
(*)(
	PHANDLE,
	ACCESS_MASK,
	POBJECT_ATTRIBUTES,
	PCLIENT_ID
	);

using FnZwTerminateProcess = NTSTATUS
(*)
(
	HANDLE,
	NTSTATUS
	);
using FnPsResumeProcess = NTSTATUS(*)(PEPROCESS);
using FnKeAttachProcess = void(*)(PEPROCESS, PKAPC_STATE);
using FnIoAllocateMdl = PMDL(*)(
	PVOID VirtualAddress,
	ULONG Length,
	BOOLEAN SecondaryBuffer,
	BOOLEAN ChargeQuota,
	PIRP Irp);
using FnMmProbeAndLockPages = void(*)(
	PMDL MemoryDescriptorList,
	KPROCESSOR_MODE AccessMode,
	LOCK_OPERATION Operation);

using FnMmMapLockedPages = PVOID(*)(
	PMDL MemoryDescriptorList,
	KPROCESSOR_MODE AccessMode);

using FnKeUnstackDetachProcess = void(*)(PKAPC_STATE);
using FnZwAllocateVirtualMemory = NTSTATUS(*)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect);
using FnZwClose = NTSTATUS(*)(HANDLE);
using FnZwFreeVirutalMemory = NTSTATUS(*)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PSIZE_T RegionSize,
	ULONG FreeType);

FnZwOpenProcess g_ZwOpenProcess;
FnZwTerminateProcess g_ZwTerminateProcess;

ULONG_PTR g_Process;
FnPsLookupProcessByProcessId g_PsLookupProcessByProcessId;
FnPsSuspendProcess g_PsSuspendProcess;
FnObDereferenceObject g_ObDereferenceObject;

FnPsResumeProcess g_ResumeProcess;

FnMmMapLockedPagesSpecifyCache g_MmMapLockedPagesSpecifyCache;
FnIoAllocateMdl g_IoAllocateMdl;
FnKeAttachProcess g_KeStackAttachProcess;
FnMmProbeAndLockPages g_MmProbeAndLockPages;
FnMmMapLockedPages g_MmMapLockedPages;
FnKeUnstackDetachProcess g_KeUnstackDetachProcess;
FnZwAllocateVirtualMemory g_ZwAllocateVirtualMemory;
FnZwClose g_ZwClose;
FnZwFreeVirutalMemory g_ZwFreeVirtualMemory;

// prototype code for Exploit::terminte_process
__declspec(noinline)
extern "C" NTSTATUS NTAPI TerminateProcess(ULONG pid)
{
	HANDLE hProcess{};
	OBJECT_ATTRIBUTES oa{};
	CLIENT_ID clientId{};

	InitializeObjectAttributes(&oa, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

	clientId.UniqueProcess = (HANDLE)pid;
	clientId.UniqueThread = nullptr; 

	auto status = g_ZwOpenProcess(&hProcess, 1, &oa, &clientId);

	if (!NT_SUCCESS(status))
		return status;

	status = g_ZwTerminateProcess(hProcess, STATUS_SUCCESS);

	g_ZwClose(hProcess);

	return status;
}

// prototype code for Exploit::suspend_process
__declspec(noinline)
extern "C" NTSTATUS NTAPI SuspendProcess(ULONG pid)
{
	PEPROCESS process{};

	auto status = reinterpret_cast<FnPsLookupProcessByProcessId>(g_PsLookupProcessByProcessId)((HANDLE)pid, &process);

	if (!NT_SUCCESS(status))
		return status;

	status = g_PsSuspendProcess(process);

	g_ObDereferenceObject(process);

	return status;
}

// prototype code for Exploit::resume_process
__declspec(noinline)
extern "C" NTSTATUS NTAPI ResumeProcess(ULONG pid)
{
	PEPROCESS process{};

	auto status = g_PsLookupProcessByProcessId((HANDLE)pid, &process);

	if (!NT_SUCCESS(status))
		return status;

	status = g_PsSuspendProcess(process);

	g_ObDereferenceObject(process);

	return status;
}

struct MapProcessMemoryArgs
{
	PMDL Mdl;
	PVOID UserVa;
};

// prototype code for Exploit::mmap_process
__declspec(noinline)
extern "C" NTSTATUS NTAPI MapProcessMemory(
	ULONG pid,
	PVOID address,
	ULONG length,
	MapProcessMemoryArgs* outArgs)
{
	PEPROCESS process{};
	KAPC_STATE state{};

	auto status = g_PsLookupProcessByProcessId((HANDLE)pid, &process);

	if (!NT_SUCCESS(status))
		return status;

	auto mdl = g_IoAllocateMdl(address, length, FALSE, FALSE, NULL);
	
	if (!mdl)
		return STATUS_NO_MEMORY;

	g_KeStackAttachProcess(process, &state);

	g_MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);

	g_KeUnstackDetachProcess(&state);

	auto userVa = g_MmMapLockedPages(mdl, UserMode);

	outArgs->Mdl = mdl;
	outArgs->UserVa = userVa;

	return status;
}

// prototype code for Exploit::allocate_process_memory
__declspec(noinline)
extern "C" NTSTATUS NTAPI AllocateProcessVirtualMemory(
	ULONG pid,
	ULONG protection,
	PVOID* address,
	SIZE_T* length)
{
	HANDLE hProcess{};
	OBJECT_ATTRIBUTES oa{};
	CLIENT_ID clientId{};

	if (!address || !length)
		return STATUS_INVALID_PARAMETER_3;

	InitializeObjectAttributes(&oa, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

	clientId.UniqueProcess = (HANDLE)pid;
	clientId.UniqueThread = nullptr;

	auto status = g_ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &clientId);

	if (!NT_SUCCESS(status))
		return status;

	PVOID allocBase{ *address };
	SIZE_T allocSize{ *length };

	status = g_ZwAllocateVirtualMemory(hProcess, &allocBase, 0, &allocSize, MEM_RESERVE | MEM_COMMIT, protection);

	if (!NT_SUCCESS(status))
	{
		g_ZwClose(hProcess);
		return status;
	}

	*address = allocBase;
	*length = allocSize;

	g_ZwClose(hProcess);

	return status;
}

// prototype code for Exploit::allocate_process_memory
__declspec(noinline)
extern "C" NTSTATUS NTAPI FreeProcessVirtualMemory(ULONG pid, PVOID address, SIZE_T length)
{
	HANDLE hProcess{};
	OBJECT_ATTRIBUTES oa{};
	CLIENT_ID clientId{};

	if (!address)
		return STATUS_INVALID_PARAMETER;

	InitializeObjectAttributes(&oa, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

	clientId.UniqueProcess = UlongToHandle(pid);
	clientId.UniqueThread = nullptr;

	auto status = g_ZwOpenProcess(&hProcess, 1, &oa, &clientId);

	if (!NT_SUCCESS(status))
		return status;

	PVOID baseAddress{ address };
	SIZE_T size{ length };

	status = g_ZwFreeVirtualMemory(hProcess, &baseAddress, &size, MEM_RELEASE);

	g_ZwClose(hProcess);

	return status;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
	UNREFERENCED_PARAMETER(driverObject);
	UNREFERENCED_PARAMETER(registryPath);

	TerminateProcess(4);
	SuspendProcess(4);

	MapProcessMemoryArgs args{};

	MapProcessMemory(0x1, (PVOID)0x1234, PAGE_SIZE, &args);

	PVOID base{};
	SIZE_T size{ PAGE_SIZE };

	AllocateProcessVirtualMemory(0x1, PAGE_READWRITE, &base, &size);

	FreeProcessVirtualMemory(0x1, (PVOID)0x1234, PAGE_SIZE);

	return STATUS_SUCCESS;
}
```