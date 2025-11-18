#pragma once

#include "if_kernel.h"
#include "elf_file.h"
#include "vmemory.h"

#include <map>
#include <memory>

namespace kernel::Linux
{
    class Linux64Kernel : public kernel::IfKernel64
    {
    public:
        void load(const elf::ElfFile64& elf_file);

        KernelType getType() const final;
        uint64_t syscall(uint64_t number, const uint64_t* args, size_t num_args) override;

        void* translate_address(std::uintptr_t address) final;
        const void* translate_address(std::uintptr_t address) const final;

        std::uintptr_t stack_address() const;

    private:
        void load_section(const elf::ElfFile64& elf_file, size_t index);
        void allocate_stack();
        std::map<std::uintptr_t, kernel::VirtualMemorySection> m_virtual_memory;
    };
};
