#pragma once

#include <cstdint>

namespace cpu::X86_64
{
    using register_t = std::uint64_t;
    using flag_t = std::uint64_t;
    using ptr_t = std::uint64_t;

    enum Register
    {
        REG_RAX = 0,
        REG_RCX,
        REG_RDX,
        REG_RBX,
        REG_RSP,
        REG_RBP,
        REG_RSI,
        REG_RDI,
        REG_R8,
        REG_R9,
        REG_R10,
        REG_R11,
        REG_R12,
        REG_R13,
        REG_R14,
        REG_R15,
    };

    enum FlagShift
    {
        FLAGSHIFT_CF = 0,
        FLAGSHIFT_ZF = 6,
        FLAGSHIFT_SF = 7,
    };

    enum Flags
    {
        FLAG_CF = 0x0001, // carry flag
        FLAG_PF = 0x0004, // parity flag
        FLAG_AF = 0x0010, // auxilary carry flag
        FLAG_ZF = 0x0040, // zero flag
        FLAG_SF = 0x0080, // sign flag
        FLAG_TF = 0x0100, // trap flag
        FLAG_IF = 0x0200, // interrupt enable flag
        FLAG_DF = 0x0400, // direction flag
        FLAG_OF = 0x0800, // overflow flag
    };

    /**
     * see 2.1.5 Addressing-Mode Encoding of ModR/M and SIB Bytes
     */
    enum ModBits : unsigned char
    {
        MOD_INDIRECT = 0x00, // Indirect memory address, no displacement
        MOD_INDIRECT_8BIT = 0x1, // Indirect memory address, 8bit displacement
        MOD_INDIRECT_32BIT = 0x2, // Indirect memory address, 8bit displacement
        MOD_DIRECT_REGISTER = 0x3, // Direct Register
    };
}
