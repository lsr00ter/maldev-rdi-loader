/**
 * @file peb.h
 * @brief Header file for PEB (Process Environment Block) related functionality.
 *
 * This file provides definitions and declarations for working with Windows
 * API functions and their hashed representations. It includes functionality
 * for retrieving function addresses by their hash values and calculating
 * CRC32b hashes for API names.
 */

#include <stdint.h>
#include "defs.h"

/**
 * @def SEED
 * @brief Seed value used for hashing.
 */
#define SEED 0xDEADDEAD
/**
 * @def HASH(API)
 * @brief Macro to compute the CRC32b hash of a given API name.
 * @param API The API name as a string.
 */
#define HASH(API) (crc32b((uint8_t *)API))

/**
 * @def RtlInitUnicodeString_CRC32b
 * @brief CRC32b hash of the "RtlInitUnicodeString" API.
 */
#define RtlInitUnicodeString_CRC32b 0xe17f353f
/**
 * @def RtlMultiByteToUnicodeN_CRC32b
 * @brief CRC32b hash of the "RtlMultiByteToUnicodeN" API.
 */
#define RtlMultiByteToUnicodeN_CRC32b 0xaba11095
/**
 * @def LdrLoadDll_CRC32b
 * @brief CRC32b hash of the "LdrLoadDll" API.
 */
#define LdrLoadDll_CRC32b 0x43638559
/**
 * @def LdrGetProcedureAddress_CRC32b
 * @brief CRC32b hash of the "LdrGetProcedureAddress" API.
 */
#define LdrGetProcedureAddress_CRC32b 0x3b93e684
/**
 * @def NtCreateFile_CRC32b
 * @brief CRC32b hash of the "NtCreateFile" API.
 */
#define NtCreateFile_CRC32b 0x962c4683
/**
 * @def NtReadFile_CRC32b
 * @brief CRC32b hash of the "NtReadFile" API.
 */
#define NtReadFile_CRC32b 0xab569438
/**
 * @def NtClose_CRC32b
 * @brief CRC32b hash of the "NtClose" API.
 */
#define NtClose_CRC32b 0xf78fd98f
/**
 * @def NtAllocateVirtualMemory_CRC32b
 * @brief CRC32b hash of the "NtAllocateVirtualMemory" API.
 */
#define NtAllocateVirtualMemory_CRC32b 0xec50426f
/**
 * @def NtReadVirtualMemory_CRC32b
 * @brief CRC32b hash of the "NtReadVirtualMemory" API.
 */
#define NtReadVirtualMemory_CRC32b 0x58bdb7be
/**
 * @def NtFreeVirtualMemory_CRC32b
 * @brief CRC32b hash of the "NtFreeVirtualMemory" API.
 */
#define NtFreeVirtualMemory_CRC32b 0xf29625d3
/**
 * @def NtProtectVirtualMemory_CRC32b
 * @brief CRC32b hash of the "NtProtectVirtualMemory" API.
 */
#define NtProtectVirtualMemory_CRC32b 0x357d60b3
/**
 * @def NtFlushInstructionCache_CRC32b
 * @brief CRC32b hash of the "NtFlushInstructionCache" API.
 */
#define NtFlushInstructionCache_CRC32b 0xc5f7ca5e
/**
 * @def NtQueryInformationFile_CRC32b
 * @brief CRC32b hash of the "NtQueryInformationFile" API.
 */
#define NtQueryInformationFile_CRC32b 0xb54956cb

/**
 * @fn void *get_ntdll()
 * @brief Retrieves the base address of the ntdll.dll module.
 * @return A pointer to the base address of ntdll.dll.
 */
extern void *get_ntdll();

/**
 * @fn uint32_t crc32b(const uint8_t *str)
 * @brief Computes the CRC32b hash of a given string.
 * @param str Pointer to the input string.
 * @return The computed CRC32b hash value.
 */
uint32_t crc32b(const uint8_t *str);

/**
 * @fn void *get_proc_address_by_hash(void *dll_address, uint32_t function_hash)
 * @brief Retrieves the address of a function in a DLL by its hash value.
 * @param dll_address Pointer to the base address of the DLL.
 * @param function_hash The CRC32b hash of the function name.
 * @return A pointer to the function's address, or NULL if not found.
 */
void *get_proc_address_by_hash(void *dll_address, uint32_t function_hash);