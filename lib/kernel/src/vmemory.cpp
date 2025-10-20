#include "vmemory.h"

using kernel::VirtualMemorySection;

VirtualMemorySection::VirtualMemorySection(uintptr_t address, uint8_t flags, size_t size)
: m_address(address)
, m_flags(flags)
, m_data(size)
{
}

VirtualMemorySection::VirtualMemorySection(uintptr_t address, uint8_t flags, std::vector<std::byte>&& data)
: m_address(address)
, m_flags(flags)
, m_data(std::move(data))
{
}
