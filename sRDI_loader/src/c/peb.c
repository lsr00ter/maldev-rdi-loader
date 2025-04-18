/**
 * @file peb.c
 * @brief Provides functionality for calculating CRC32 hash and retrieving function addresses by hash from a DLL.
 */

#include "peb.h"
#include <stdint.h>

/**
 * @brief Computes the CRC32 hash of a given null-terminated string.
 *
 * This function calculates the CRC32 checksum for a given string using a specified seed value.
 *
 * @param str A pointer to the null-terminated string to hash.
 * @return The computed CRC32 hash value.
 */
uint32_t crc32b(const uint8_t *str)
{
    uint32_t crc = 0xFFFFFFFF;
    uint32_t byte;
    uint32_t mask;
    int i = 0x0;
    int j;

    while (str[i] != 0)
    {
        byte = str[i];
        crc = crc ^ byte;
        for (j = 7; j >= 0; j--)
        {
            mask = -1 * (crc & 1);
            crc = (crc >> 1) ^ (SEED & mask);
        }
        i++;
    }
    return ~crc;
}

/**
 * @brief Retrieves the address of a function in a DLL by its hash.
 *
 * This function iterates through the export table of a given DLL to find a function whose name
 * matches the provided hash. If a match is found, the function's address is returned.
 *
 * @param dll_address A pointer to the base address of the loaded DLL.
 * @param function_hash The hash of the function name to search for.
 * @return A pointer to the function's address if found, or NULL if not found.
 */
void *get_proc_address_by_hash(void *dll_address, uint32_t function_hash)
{
    void *base = dll_address;
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)base + dos_header->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY export_directory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)base +
                                                                         nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    unsigned long *p_address_of_functions = (PDWORD)((DWORD_PTR)base + export_directory->AddressOfFunctions);
    unsigned long *p_address_of_names = (PDWORD)((DWORD_PTR)base + export_directory->AddressOfNames);
    unsigned short *p_address_of_name_ordinals = (PWORD)((DWORD_PTR)base + export_directory->AddressOfNameOrdinals);

    for (unsigned long i = 0; i < export_directory->NumberOfNames; i++)
    {
        LPCSTR p_function_name = (LPCSTR)((DWORD_PTR)base + p_address_of_names[i]);
        unsigned short p_function_ordinal = (unsigned short)p_address_of_name_ordinals[i];
        unsigned long p_function_address = (unsigned long)p_address_of_functions[p_function_ordinal];

        if (function_hash == HASH(p_function_name))
            return (void *)((DWORD_PTR)base + p_function_address);
    }
    return NULL;
}