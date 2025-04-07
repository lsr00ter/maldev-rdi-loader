/**
 * @file defs.h
 * @brief Contains macro definitions, constants, and typedefs for various Windows API functions and structures.
 *
 * This header file provides:
 * - Macros for obtaining current thread and process handles.
 * - Definitions for object attributes used in Windows kernel operations.
 * - Typedefs for function pointers to various Windows API functions, including file operations,
 *   memory management, and DLL handling.
 *
 * Macros:
 * - `NtCurrentThread()`: Retrieves the current thread handle.
 * - `NtCurrentProcess()`: Retrieves the current process handle.
 * - `RTL_CONSTANT_STRING(s)`: Macro for initializing a constant Unicode string.
 * - Object attribute flags such as `OBJ_INHERIT`, `OBJ_PERMANENT`, `OBJ_EXCLUSIVE`, etc., used in object creation and manipulation.

 * Typedefs:
 * - `DLLEntry`: Function pointer for DLL entry point.
 * - `PIO_APC_ROUTINE`: Function pointer for APC (Asynchronous Procedure Call) routine.
 * - `RtlInitUnicodeString_t`: Function pointer for initializing a Unicode string.
 * - `NtClose_t`: Function pointer for closing a handle.
 * - `RtlMultiByteToUnicodeN_t`: Function pointer for converting a multibyte string to Unicode.
 * - `NtReadFile_t`: Function pointer for reading from a file.
 * - `LdrLoadDll_t`: Function pointer for loading a DLL.
 * - `LdrGetProcedureAddress_t`: Function pointer for retrieving a procedure address from a DLL.
 * - `NtCreateFile_t`: Function pointer for creating or opening a file.
 * - `NtAllocateVirtualMemory_t`: Function pointer for allocating virtual memory.
 * - `NtProtectVirtualMemory_t`: Function pointer for changing memory protection.
 * - `NtFreeVirtualMemory_t`: Function pointer for freeing virtual memory.
 * - `NtReadVirtualMemory_t`: Function pointer for reading virtual memory.
 * - `NtFlushInstructionCache_t`: Function pointer for flushing the instruction cache.
 * - `NtQueryInformationFile_t`: Function pointer for querying file information.
 *
 * These definitions are intended for use in low-level Windows programming, particularly in scenarios
 * involving direct interaction with the Windows Native API.
 */

#include "structs.h"

#define NtCurrentThread() ((HANDLE)(LONG_PTR) - 2)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR) - 1)
#define RTL_CONSTANT_STRING(s) {sizeof(s) - sizeof((s)[0]), sizeof(s), s}

#define OBJ_INHERIT 0x00000002L
#define OBJ_PERMANENT 0x00000010L
#define OBJ_EXCLUSIVE 0x00000020L
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define OBJ_OPENIF 0x00000080L
#define OBJ_OPENLINK 0x00000100L
#define OBJ_KERNEL_HANDLE 0x00000200L
#define OBJ_FORCE_ACCESS_CHECK 0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP 0x00000800
#define OBJ_DONT_REPARSE 0x00001000
#define OBJ_VALID_ATTRIBUTES 0x00001FF2

typedef BOOL(__stdcall *DLLEntry)(HINSTANCE dll, unsigned long reason, void *reserved);

typedef BOOL(__stdcall *DLLEntry)(HINSTANCE dll, unsigned long reason, void *reserved);

typedef VOID(__stdcall *PIO_APC_ROUTINE)(PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG Reserved);

typedef VOID(__stdcall *RtlInitUnicodeString_t)(PUNICODE_STRING DestinationString, PWSTR SourceString);

typedef NTSTATUS(__stdcall *NtClose_t)(HANDLE);

typedef NTSTATUS(__stdcall *RtlMultiByteToUnicodeN_t)(PWCH UnicodeString, ULONG MaxBytesInUnicodeString,
                                                      PULONG BytesInUnicodeString, PCSTR MultiByteString,
                                                      ULONG BytesInMultiByteString);

typedef NTSTATUS(__stdcall *NtReadFile_t)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
                                          PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length,
                                          PLARGE_INTEGER ByteOffset, PULONG Key);

typedef NTSTATUS(__stdcall *LdrLoadDll_t)(PCWSTR DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName,
                                          PVOID *DllHandle);

typedef NTSTATUS(__stdcall *LdrGetProcedureAddress_t)(PVOID DllHandle, PANSI_STRING ProcedureName,
                                                      ULONG ProcedureNumber, PVOID *ProcedureAddress);

typedef NTSTATUS(__stdcall *NtCreateFile_t)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
                                            POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
                                            PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess,
                                            ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer,
                                            ULONG EaLength);

typedef NTSTATUS(__stdcall *NtAllocateVirtualMemory_t)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
                                                       PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

typedef NTSTATUS(__stdcall *NtProtectVirtualMemory_t)(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
                                                      DWORD NewProtect, PULONG OldProtect);

typedef NTSTATUS(__stdcall *NtFreeVirtualMemory_t)(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
                                                   ULONG FreeType);

typedef NTSTATUS(__stdcall *NtReadVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
                                                   SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);

typedef NTSTATUS(__stdcall *NtFlushInstructionCache_t)(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T Length);

typedef NTSTATUS(__stdcall *NtQueryInformationFile_t)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock,
                                                      PVOID FileInformation, ULONG Length,
                                                      FILE_INFORMATION_CLASS FileInformationClass);
