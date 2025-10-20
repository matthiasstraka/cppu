#pragma once

#include "if_kernel.h"

namespace kernel
{
    class MemoryAdapter : public IfKernel64
    {
    public:
        MemoryAdapter(void* phy_address, std::uintptr_t virt_address)
        : m_phyiscal_address(phy_address)
        , m_virt_address(virt_address)
        , m_readonly(false)
        {
        }

        MemoryAdapter(const void* phy_address, std::uintptr_t virt_address)
        : m_phyiscal_address(const_cast<void*>(phy_address))
        , m_virt_address(virt_address)
        , m_readonly(true)
        {
        }

        KernelType getType() const override
        {
            return KernelType::None;
        }
        
        uint64_t syscall(uint64_t number, const uint64_t* args, size_t num_args) override
        {
            return 0;
        }

        void* translate_address(std::uintptr_t addr) override
        {
            if (m_readonly)
            {
                return nullptr;
            }
            return reinterpret_cast<char*>(m_phyiscal_address) + (addr - m_virt_address);
        }

        const void* translate_address(std::uintptr_t addr) const override
        {
            return reinterpret_cast<char*>(m_phyiscal_address) + (addr - m_virt_address);
        }

    private:
        void* m_phyiscal_address;
        std::uintptr_t m_virt_address;
        bool m_readonly;
    };
}
