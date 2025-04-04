#include <stdint.h>
#include "defs.h"

#define SEED 0xDEADDEAD
#define HASH(API)(crc32b((uint8_t *)API))

#define RtlInitUnicodeString_CRC32b         0xe17f353f
#define RtlMultiByteToUnicodeN_CRC32b       0xaba11095
#define LdrLoadDll_CRC32b                   0x43638559
#define LdrGetProcedureAddress_CRC32b       0x3b93e684
#define NtCreateFile_CRC32b                 0x962c4683
#define NtReadFile_CRC32b                   0xab569438
#define NtClose_CRC32b                      0xf78fd98f
#define NtAllocateVirtualMemory_CRC32b      0xec50426f
#define NtReadVirtualMemory_CRC32b          0x58bdb7be
#define NtFreeVirtualMemory_CRC32b          0xf29625d3
#define NtProtectVirtualMemory_CRC32b       0x357d60b3
#define NtFlushInstructionCache_CRC32b      0xc5f7ca5e
#define NtQueryInformationFile_CRC32b       0xb54956cb

extern void *get_ntdll();

uint32_t crc32b(const uint8_t *str);

void *get_proc_address_by_hash(void *dll_address, uint32_t function_hash);