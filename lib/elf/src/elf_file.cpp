#include "elf_file.h"

#include <stdexcept>

using elf::ElfFile64;

ElfFile64::ElfFile64(const std::string& filename)
{
    m_file = fopen(filename.c_str(), "rb");
    if (!m_file)
    {
        throw std::runtime_error("Cannot open ELF file");
    }
    fseek(m_file, 0, SEEK_SET);
    if (1 != fread(&m_ident, sizeof(ElfIdent), 1, m_file))
    {
        throw std::runtime_error("Cannot read ELF magic number");
    }
    if (m_ident.ei_magic[0] != 0x7F || m_ident.ei_magic[1] != 'E' || m_ident.ei_magic[2] != 'L' || m_ident.ei_magic[3] != 'F')
    {
        throw std::runtime_error("Invalid ELF magic number");
    }
    if (m_ident.ei_class != elf::ElfClass::ELF64)
    {
        throw std::runtime_error("Invalid ELF64 file");
    }

    if (1 != fread(&m_header, sizeof(ElfHeader64), 1, m_file))
    {
        throw std::runtime_error("Cannot read program header");
    }
    if (m_header.e_phentsize != sizeof(ProgramHeader64))
    {
        throw std::runtime_error("Program header size invalid");
    }
    if (m_header.e_shentsize != sizeof(SectionHeader64))
    {
        throw std::runtime_error("Section header size invalid");
    }
    
    fseek(m_file, m_header.e_phoff, SEEK_SET);
    m_p_header.resize(m_header.e_phnum);
    if (m_header.e_phnum != fread(m_p_header.data(), sizeof(ProgramHeader64), m_header.e_phnum, m_file))
    {
        throw std::runtime_error("Cannot read program headers");
    }
    
    fseek(m_file, m_header.e_shoff, SEEK_SET);
    m_s_header.resize(m_header.e_shnum);
    if (m_header.e_shnum != fread(m_s_header.data(), sizeof(SectionHeader64), m_header.e_shnum, m_file))
    {
        throw std::runtime_error("Cannot read section headers");
    }

    if (m_header.e_shstrndx >= m_s_header.size())
    {
        throw std::runtime_error("Invalid string section");
    }

    const auto& string_section = m_s_header[m_header.e_shstrndx];
    fseek(m_file, string_section.sh_offset, SEEK_SET);
    m_string_data.resize(string_section.sh_size);
    if (1 != fread(m_string_data.data(), string_section.sh_size, 1, m_file))
    {
        throw std::runtime_error("Cannot read string data");
    }
}

ElfFile64::~ElfFile64()
{
    if (m_file)
    {
        fclose(m_file);
    }
}

std::string_view ElfFile64::getString(size_t index) const
{
    if (index >= m_string_data.size())
    {
        throw std::runtime_error("Index out of range");
    }

    return m_string_data.data() + index;
}

std::vector<std::byte> ElfFile64::getSectionData(size_t index) const
{
    if (index >= m_p_header.size())
    {
        throw std::runtime_error("Index out of range");
    }

    const auto& hdr = m_p_header[index];

    std::vector<std::byte> data(hdr.p_memsz);
    fseek(m_file, hdr.p_offset, SEEK_SET);
    fread(data.data(), data.size(), 1, m_file);
    return data;
}
