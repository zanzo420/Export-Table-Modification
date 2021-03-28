#include <Windows.h>
#include <iostream>


#define IS_RE(Characteristics) (Characteristics & IMAGE_SCN_CNT_CODE && Characteristics & IMAGE_SCN_MEM_EXECUTE && Characteristics & IMAGE_SCN_MEM_READ)



//we love lambda and auto abuse :D
uintptr_t GetLibraryExport(uintptr_t BaseAddressOfModule, std::string Function)
{
    auto GetExportDirectory = [&](uintptr_t ImageBase)
    {
        auto DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
        auto NtHeader = (PIMAGE_NT_HEADERS64)(ImageBase + DosHeader->e_lfanew);

        return (PIMAGE_EXPORT_DIRECTORY)(ImageBase + NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress);
    };

    auto Exports = GetExportDirectory(BaseAddressOfModule);

    auto ExportNames = (DWORD*)((DWORD*)(BaseAddressOfModule + Exports->AddressOfNames));
    auto ExportFunctionAddresses = (DWORD*)((DWORD*)(BaseAddressOfModule + Exports->AddressOfFunctions));

    for (int i = 0; i < Exports->NumberOfNames; i++)
    {
        if (!strcmp(Function.c_str(), (char*)(BaseAddressOfModule + ExportNames[i])))
            return (uintptr_t)(BaseAddressOfModule + ExportFunctionAddresses[i + 1]);
    }

    return 0;
}

uintptr_t ModifyExport(uintptr_t BaseAddressOfModule, std::string Function, void* FunctionAddress, void** OriginalPtr)
{
    auto FindCodeCave = [&](uintptr_t ImageBase, int SizeOfCodeCave)
    {
        auto DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
        auto NtHeader = (PIMAGE_NT_HEADERS64)(ImageBase + DosHeader->e_lfanew);

        auto SectionHeader = IMAGE_FIRST_SECTION(NtHeader);

        int ConsecutivePadding = 0;
        uintptr_t CodeCaveAddress = 0;

        for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++, SectionHeader++)
            if (IS_RE(SectionHeader->Characteristics))
            {
                for (uintptr_t b = 0;; b++)
                {
                    void* Address = (void*)(ImageBase + SectionHeader->VirtualAddress + b);

                    unsigned char CurrentByte = *(unsigned char*)(Address);
                    if (CurrentByte == 0xCC || CurrentByte == 0x00)
                        ConsecutivePadding++;
                    else
                        ConsecutivePadding = 0;

                    if (ConsecutivePadding > SizeOfCodeCave)
                    {
                        CodeCaveAddress = (uintptr_t)Address - ConsecutivePadding;
                        break;
                    }
                }
                break;
            }

        return CodeCaveAddress;
    };

    auto GetExportDirectory = [&](uintptr_t ImageBase)
    {
        auto DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
        auto NtHeader = (PIMAGE_NT_HEADERS64)(ImageBase + DosHeader->e_lfanew);

        return (PIMAGE_EXPORT_DIRECTORY)(ImageBase + NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress);
    };

    auto WriteToNonWritableRegion = [&](uintptr_t Address, uintptr_t WriteAddress, int Size)
    {
        DWORD Old;

        VirtualProtect((void*)Address, Size, PAGE_EXECUTE_READWRITE, &Old);
        memcpy((void*)Address, (void*)WriteAddress, Size);
        VirtualProtect((void*)Address, Size, PAGE_EXECUTE_READ, &Old);
    };

    auto CreateJump = [&](uintptr_t Address, uintptr_t JumpTo)
    {
        // funny number :flushed:
        unsigned char JumpInstruction[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69 };
        *(uintptr_t*)(JumpInstruction + 6) = JumpTo;

        WriteToNonWritableRegion(Address, (uintptr_t)&JumpInstruction, sizeof(JumpInstruction));
    };


    auto Exports = GetExportDirectory(BaseAddressOfModule);

    auto pExportNames = (DWORD*)((DWORD*)(BaseAddressOfModule + Exports->AddressOfNames));
    auto pExportFunctionAddresses = (DWORD*)((DWORD*)(BaseAddressOfModule + Exports->AddressOfFunctions));

    for (int i = 0; i < Exports->NumberOfNames; i++)
    {
        if (!strcmp(Function.c_str(), (char*)(BaseAddressOfModule + pExportNames[i])))
        {
            DWORD old;
            void* Addr = (void*)(pExportFunctionAddresses + i + 1);

            *OriginalPtr = (void*)(BaseAddressOfModule + *(DWORD*)(Addr));

            auto CodeCave = FindCodeCave(BaseAddressOfModule, 14);
            auto CodeCaveForImport = (DWORD)(CodeCave - BaseAddressOfModule);

            CreateJump(CodeCave, (uintptr_t)FunctionAddress);
            WriteToNonWritableRegion((uintptr_t)Addr, (uintptr_t)&CodeCaveForImport, sizeof(DWORD));

            break;
        }
    }

    return 0;
}


typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

NTSTATUS(*NtQueryVirtualMemoryOriginal)
(
    HANDLE                   ProcessHandle,
    PVOID                    BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID                    MemoryInformation,
    SIZE_T                   MemoryInformationLength,
    PSIZE_T                  ReturnLength
    );

NTSTATUS NtQueryVirtualMemoryHooked
(
    HANDLE                   ProcessHandle,
    PVOID                    BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID                    MemoryInformation,
    SIZE_T                   MemoryInformationLength,
    PSIZE_T                  ReturnLength
)
{
    printf("NtQueryVirtualMemory Hook Called\nAddress Queryied: 0x%p\nMemoryInformationClass: %d\n\n", BaseAddress, MemoryBasicInformation);
    return NtQueryVirtualMemoryOriginal(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
}

int main()
{
    uintptr_t ModuleBase = (uintptr_t)GetModuleHandleA("ntdll.dll");

    ModifyExport(ModuleBase, "NtQueryVirtualMemory", NtQueryVirtualMemoryHooked, (void**)&NtQueryVirtualMemoryOriginal);


    auto NtQueryVirtualMemoryAddress_A = GetLibraryExport(ModuleBase, "NtQueryVirtualMemory");

    NTSTATUS(*NtQueryVirtualMemory_B)
        (
            HANDLE                   ProcessHandle,
            PVOID                    BaseAddress,
            MEMORY_INFORMATION_CLASS MemoryInformationClass,
            PVOID                    MemoryInformation,
            SIZE_T                   MemoryInformationLength,
            PSIZE_T                  ReturnLength
            ) = decltype(NtQueryVirtualMemory_B)(GetProcAddress((HMODULE)ModuleBase, "NtQueryVirtualMemory"));


    printf("NtQueryVirtualMemory codecave from GetLibraryExport: 0x%p\n", NtQueryVirtualMemoryAddress_A);
    printf("NtQueryVirtualMemory codecave from GetProcAddress: 0x%p\n\n", NtQueryVirtualMemory_B);

    printf("NtQueryVirtualMemoryHook: 0x%p\n", NtQueryVirtualMemoryHooked);
    printf("NtQueryVirtualMemoryOriginal: 0x%p\n\n", NtQueryVirtualMemoryOriginal);


    MEMORY_BASIC_INFORMATION BasicInfo;
    SIZE_T RetSize;
    NtQueryVirtualMemory_B((HANDLE)-1, main, MEMORY_INFORMATION_CLASS::MemoryBasicInformation, &BasicInfo, sizeof(BasicInfo), &RetSize);

    system("pause");

    return 0;
}
