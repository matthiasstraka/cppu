#pragma once
/**
 * see https://wiki.osdev.org/CPU_Registers_x86-64
 */

#include "x86-64_structs.h"
#include "if_kernel.h"

#include <array>
#include <cstddef>
#include <cstdint>

namespace cpu::X86_64
{
    class CPU
    {
    public:
        CPU(kernel::IfKernel64* kernel = nullptr);

        ptr_t getIP() const { return m_ip; }
        void setIP(ptr_t ip) { m_ip = ip; }

        flag_t getFlags() const { return m_flags; }

        register_t getRegister(Register reg) const { return m_registers[static_cast<size_t>(reg)]; }
        void setRegister(Register reg, register_t value) { m_registers[static_cast<size_t>(reg)] = value; }

        void execute_next();
        ptr_t execute_one(ptr_t ip);

    private:
        const std::uint8_t* translate_instruction_address(ptr_t address);
        const std::uint8_t* get_instruction_address(ptr_t address) const;
        template<typename T>
        const T& fetch_imm(ptr_t address) const;

        std::pair<uint64_t, size_t> decode_address(ModBits mod, uint8_t rm, const Instruction& inst, const uint8_t* p);

        uint8_t& reg8(uint8_t reg, bool with_rex, bool extension);
        uint16_t& reg16(uint8_t reg);
        uint32_t& reg32(uint8_t reg);
        uint64_t& reg64(uint8_t reg, bool extension);

        template<typename T>
        void store(ptr_t address, T);

        template<typename T>
        T load(ptr_t address) const;

        using Executor = ptr_t(CPU::*)(Instruction&, ptr_t ip);
        struct OpCode {
            OpCode(Executor executor, bool is_prefix = false)
                : f(executor)
                , prefix(is_prefix)
            {}

            operator bool() const { return f != nullptr; }
            Executor f;
            bool prefix;
        };
        template<uint8_t code>
        ptr_t decode_prefix(Instruction&, ptr_t ip);
        template<typename Op> ptr_t op_al_imm8(Instruction&, ptr_t ip);
        template<typename Op> ptr_t op_eax_imm32(Instruction&, ptr_t ip);
        template<typename Op> ptr_t op_rm8_r8(Instruction&, ptr_t ip);
        template<typename Op> ptr_t op_rm32_r32(Instruction&, ptr_t ip);
        ptr_t execute_MOV_8A(Instruction&, ptr_t ip); // MOV r8, r/m8
        ptr_t execute_MOV_8B(Instruction&, ptr_t ip); // MOV r32, r/m32
        ptr_t execute_MOV_B0(Instruction&, ptr_t ip); // MOV r8, imm8
        ptr_t execute_MOV_B8(Instruction&, ptr_t ip); // MOV r32, imm32
        ptr_t execute_Jcc_7x(Instruction&, ptr_t ip);
        ptr_t execute_JMP(Instruction&, ptr_t ip);
        ptr_t execute_HLT_F4(Instruction&, ptr_t ip);
        ptr_t execute_CMC_F5(Instruction&, ptr_t ip);
        ptr_t execute_CLC_F8(Instruction&, ptr_t ip);
        ptr_t execute_STC_F9(Instruction&, ptr_t ip);
        ptr_t execute_CLI_FA(Instruction&, ptr_t ip);
        ptr_t execute_STI_FB(Instruction&, ptr_t ip);
        ptr_t execute_CLD_FC(Instruction&, ptr_t ip);
        ptr_t execute_STD_FD(Instruction&, ptr_t ip);
        ptr_t execute_0F(Instruction&, ptr_t ip);

        template<typename Op, typename T>
        static void op_r_r(T& first, T second, cpu::X86_64::flag_t& flags);

        template<typename Op, typename T>
        void op_m_r(ptr_t first, T second, cpu::X86_64::flag_t& flags);

        /**
         * Forwards a syscall to the kernel instance
         */
        void dispatch_syscall(ptr_t next_ip);

        std::array<register_t, 16> m_registers;
        std::array<std::uint16_t, 6> m_segment_registers;
        flag_t m_flags = 0x0020;
        ptr_t m_ip = 0;
        kernel::IfKernel64* m_kernel;
        std::uintptr_t m_ip_address_offset = 0;

        static std::array<OpCode, 256> s_opcodes;
    };
}
