#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#define PF_X 1
#define PF_W 2
#define PF_R 4

namespace kernel
{
    class VirtualMemorySection
    {
    public:
        VirtualMemorySection(uintptr_t address, uint8_t flags, size_t size);
        VirtualMemorySection(uintptr_t address, uint8_t flags, std::vector<std::byte>&& data);
    private:
        uintptr_t m_address;
        uint8_t m_flags;
        std::vector<std::byte> m_data;
    };
}
