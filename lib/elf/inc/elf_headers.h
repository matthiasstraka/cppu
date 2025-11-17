#pragma once

#include <cstdint>

// see https://en.wikipedia.org/wiki/Executable_and_Linkable_Format

namespace elf
{
    enum class ElfClass : unsigned char
    {
        ELF32 = 1,
        ELF64 = 2,
    };

    enum class ElfEndianess : unsigned char
    {
        LittleEndian = 1,
        BigEndian = 2,
    };

    enum class ElfOsAbi : unsigned char
    {
        SystemV = 0,
        Linux = 3,
    };

    enum class ISA : unsigned short
    {
        x86 = 0x03,
        IA64 = 0x32,
        AMD64 = 0x3E,
    };

    struct ElfIdent
    {
        char ei_magic[4];
        ElfClass ei_class;
        ElfEndianess ei_endian;
        unsigned char ei_version;
        ElfOsAbi ei_os_abi;
        unsigned char ei_abi_version;
        char ei_padding[7];
    };

    struct ElfHeader64
    {
        std::uint16_t e_type;
        ISA e_machine;
        std::uint32_t e_version;
        std::uint64_t e_entry;
        std::uint64_t e_phoff;
        std::uint64_t e_shoff;
        std::uint32_t e_flags;
        std::uint16_t e_shsize;
        std::uint16_t e_phentsize;
        std::uint16_t e_phnum;
        std::uint16_t e_shentsize;
        std::uint16_t e_shnum;
        std::uint16_t e_shstrndx;
    };

    enum ProgramHeaderType : std::uint32_t
    {
        PT_NULL = 0,
        PT_LOAD = 1,
        PT_DYNAMIC = 2,
        PT_INTERP = 3,
        PT_NOTE = 4,
        PT_SHLIB = 5,
        PT_PHDR = 6,
        PT_TLS = 7,
    };

    enum ProgramFlag
    {
        PF_X = 1,
        PF_W = 2,
        PF_R = 4,
    };

    struct ProgramHeader64
    {
        ProgramHeaderType p_type;
        std::uint32_t p_flags;
        std::uint64_t p_offset;
        std::uint64_t p_vaddr;
        std::uint64_t p_paddr;
        std::uint64_t p_filesz;
        std::uint64_t p_memsz;
        std::uint32_t p_align;
    };

    enum SectionHeaderType : std::uint32_t
    {
        SHT_NULL = 0x00,
        SHT_PROGBITS = 0x01,
        SHT_SYMTAB = 0x02,
        SHT_STRTAB = 0x03,
        SHT_RELA = 0x04,
        SHT_HASH = 0x05,
        SHT_DYNAMIC = 0x06,
        SHT_NOTE = 0x07,
        SHT_NOBITS = 0x08,
        SHT_REL = 0x09,
        SHT_SHLIB = 0x0A,
        SHT_DYNSYM = 0x0B,
        SHT_INIT_ARRAY = 0x0E,
        SHT_FINI_ARRAY = 0x0F,
        SHT_PREINIT_ARRAY = 0x10,
        SHT_GROUP = 0x11,
    };

    enum SectionHeaderFlag : std::uint32_t
    {
        SHF_WRITE = 0x01, // Writable
        SHF_ALLOC = 0x02, // Occupies memory during execution
        SHF_EXECINSTR = 0x04, // Executable
    };

    struct SectionHeader64
    {
        std::uint32_t sh_name;
        SectionHeaderType sh_type;
        std::uint64_t sh_flags;
        std::uint64_t sh_addr;
        std::uint64_t sh_offset;
        std::uint64_t sh_size;
        std::uint32_t sh_link;
        std::uint32_t sh_info;
        std::uint64_t sh_addralign;
        std::uint64_t sh_entsize;
    };
}