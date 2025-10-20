#include "linux64_kernel.h"

using kernel::Linux::Linux64Kernel;

kernel::KernelType Linux64Kernel::getType() const
{
    return kernel::KernelType::Linux64;
}

uint64_t Linux64Kernel::syscall(uint64_t number, const uint64_t* args, size_t num_args)
{
    return 0;
}
