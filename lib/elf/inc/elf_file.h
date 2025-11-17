#pragma once

#include "elf_headers.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace elf
{
    class ElfFile64
    {
    public:
        ElfFile64(const std::string& filename);
        ~ElfFile64();

        const ProgramHeader64& getProgramSection(size_t index) const { return m_p_header[index]; }
        size_t getNumProgramSections() const { return m_p_header.size(); }

        std::string_view getString(size_t index) const;
        std::vector<std::byte> getSectionData(size_t index) const;

    private:
        FILE* m_file = nullptr;
        ElfIdent m_ident;
        ElfHeader64 m_header;
        std::vector<ProgramHeader64> m_p_header;
        std::vector<SectionHeader64> m_s_header;
        std::vector<char> m_string_data;
    };
}
