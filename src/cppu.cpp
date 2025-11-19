#include <elf_file.h>
#include <linux64_kernel.h>
#include <x86-64.h>

#include <string>
#include <iostream>

int main(int argc, char* argv[])
{
    // TODO: parse actual filename
    const std::string filename = TEST_FILES_PATH "simple/simple.bin";

    try
    {
        kernel::Linux::Linux64Kernel kernel;
        elf::ElfFile64 binary(filename);
        kernel.load(binary);

        cpu::X86_64::CPU cpu(&kernel);
        cpu.setIP(binary.header().e_entry);
        cpu.setRegister(cpu::X86_64::REG_RSP, kernel.stack_address());

        // TODO: properly execute
        cpu.execute_next();
        cpu.execute_next();
        cpu.execute_next();
        cpu.execute_next();
        return static_cast<int>(cpu.getRegister(cpu::X86_64::REG_RAX));
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }

    return 0;
}
