#pragma once

#include <cstddef>
#include <cstdint>

namespace kernel
{
    enum class KernelType
    {
        None,
        Linux64,
    };

    class IfKernel64
    {
    public:
        /**
         * Returns the type of kernel
         */
        virtual KernelType getType() const = 0;

        /**
         * Makes a syscall into the kernel
         */
        virtual uint64_t syscall(uint64_t number, const uint64_t* args, size_t num_args) = 0;

        /**
         * Translate a virtual memory address for R/W memory
         */
        virtual void* translate_address(std::uintptr_t address) = 0;
        /**
         * Translate a virtual memory address for read-only memory
         */
        virtual const void* translate_address(std::uintptr_t address) const = 0;
    };
}
