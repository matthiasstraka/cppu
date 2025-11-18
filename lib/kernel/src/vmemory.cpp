#include "vmemory.h"

#include <cstring>
#include <new>

using kernel::VirtualMemorySection;

VirtualMemorySection::VirtualMemorySection(size_t size, std::align_val_t alignment, uint8_t flags)
    : m_size(size)
    , m_alignment(alignment)
    , m_flags(flags)
{
    m_data = reinterpret_cast<std::byte*>(::operator new(m_size, std::align_val_t(alignment)));
}

VirtualMemorySection::VirtualMemorySection(size_t size, std::align_val_t alignment, uint8_t flags, std::byte init)
    : m_size(size)
    , m_alignment(alignment)
    , m_flags(flags)
{
    m_data = reinterpret_cast<std::byte*>(::operator new(m_size, std::align_val_t(alignment)));
    std::memset(m_data, static_cast<int>(init), m_size);
}

VirtualMemorySection::~VirtualMemorySection()
{
    ::operator delete(m_data, m_alignment);
}
