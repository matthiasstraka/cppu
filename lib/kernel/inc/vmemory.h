#pragma once

#include <cstddef>
#include <cstdint>
#include <new>

#define PF_X 1
#define PF_W 2
#define PF_R 4

namespace kernel
{
    class VirtualMemorySection
    {
    public:
        /**
         * Creates a section with uninitialzed data
         */
        VirtualMemorySection(size_t size, std::align_val_t alignment, uint8_t flags);
        VirtualMemorySection(size_t size, std::align_val_t alignment, uint8_t flags, std::byte init);
        ~VirtualMemorySection();
        VirtualMemorySection(const VirtualMemorySection&) = delete;

        uintptr_t size() const { return m_size; }
        std::byte* data() { return m_data; }
        const std::byte* data() const { return m_data; }

    private:
        size_t m_size;
        std::byte* m_data;
        std::align_val_t m_alignment;
        uint8_t m_flags;
    };
}
