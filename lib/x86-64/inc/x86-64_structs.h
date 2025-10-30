#pragma once

#include "x86-64_types.h"
#include <cstdint>

namespace cpu::X86_64
{
    struct ModRM
    {
        uint8_t rm : 3;
        uint8_t reg : 3;
        ModBits mod : 2;
    };

    struct SIB
    {
        uint8_t base : 3;
        uint8_t index : 3;
        uint8_t scale : 2;
    };

    struct Instruction
    {
        uint8_t opcode;
        union
        {
            struct
            {
                bool rex_b : 1;
                bool rex_x : 1;
                bool rex_r : 1;
                bool rex_w : 1;
            };
            uint8_t rex : 8;
        };
        ModRM mod_rm;
        SIB sib;
        int32_t displacement;
        int32_t imm;
        bool escape : 1; // code has 0x0F prefix
        bool lock : 1;
        bool rep_ne : 1;
        bool rep : 1;
        bool operand_size_override : 1; // IP_OPERAND_SIZE_OVERRIDE (0x66)
        bool address_size_override : 1; // IP_ADDRESS_SIZE_OVERRIDE (0x67)
    };
}
