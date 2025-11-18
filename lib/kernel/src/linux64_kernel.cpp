#include "linux64_kernel.h"

#include <cassert>
#include <stdexcept>

using kernel::Linux::Linux64Kernel;

kernel::KernelType Linux64Kernel::getType() const
{
    return kernel::KernelType::Linux64;
}

void Linux64Kernel::load(const elf::ElfFile64& elf_file)
{
    for (size_t ps = 0; ps < elf_file.getNumProgramSections(); ++ps)
    {
        const elf::ProgramHeader64& section = elf_file.getProgramSection(ps);

        switch (section.p_type)
        {
        case elf::ProgramHeaderType::PT_LOAD:
            load_section(elf_file, ps);
            break;
        }
    }

    allocate_stack();
}

void Linux64Kernel::load_section(const elf::ElfFile64& elf_file, size_t index)
{
    const elf::ProgramHeader64& section = elf_file.getProgramSection(index);
    std::align_val_t alignment = static_cast<std::align_val_t>(section.p_align);
    auto mem = m_virtual_memory.try_emplace(section.p_vaddr,
        section.p_memsz, alignment, section.p_flags);
    if (!mem.second)
    {
        throw std::runtime_error("Cannot allocate memory for section");
    }

    auto& vmem = mem.first->second; 
    elf_file.readProgramSection(index, vmem.data(), vmem.size());
}

std::uintptr_t Linux64Kernel::stack_address() const
{
    return 0xFFFF0000; // TODO: find better address
}

void Linux64Kernel::allocate_stack()
{
    std::align_val_t alignment = static_cast<std::align_val_t>(4096);
    size_t initial_size = 1024 * 1024;
    auto addr = stack_address() - initial_size;
    m_virtual_memory.try_emplace(addr,
        initial_size, alignment, PF_R | PF_W, std::byte(0));
}

uint64_t Linux64Kernel::syscall(uint64_t number, const uint64_t* args, size_t num_args)
{
    return 0;
}

void* Linux64Kernel::translate_address(std::uintptr_t address)
{
    auto it = m_virtual_memory.upper_bound(address);
    if (!m_virtual_memory.empty())
    {
        --it;
    }

    assert(address >= it->first);
    auto offset = address - it->first;
    if (offset >= it->second.size())
    {
        return nullptr;
    }

    return it->second.data() + offset;
}

const void* Linux64Kernel::translate_address(std::uintptr_t address) const
{
    auto it = m_virtual_memory.upper_bound(address);
    if (!m_virtual_memory.empty())
    {
        --it;
    }

    assert(address >= it->first);
    auto offset = address - it->first;
    if (offset >= it->second.size())
    {
        return nullptr;
    }

    return it->second.data() + offset;
}
