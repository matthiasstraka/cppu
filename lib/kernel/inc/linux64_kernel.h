#pragma once

#include "if_kernel.h"

namespace kernel::Linux
{
    class Linux64Kernel : public kernel::IfKernel64
    {
    public:
        KernelType getType() const final;
        uint64_t syscall(uint64_t number, const uint64_t* args, size_t num_args) override;
    };
};
