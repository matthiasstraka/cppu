#include "x86-64.h"
#include "x86-64_ops.h"
#include "x86-64_structs.h"

#include <bit>
#include <cassert>
#include <stdexcept>

using cpu::X86_64::CPU;
using cpu::X86_64::ptr_t;

/**
 * see 2.1.1 Instruction Prefixes
 */
enum InstructionPrefix
{
    IP_HINT_BRANCH_NOT_TAKEN = 0x2E,
    IP_HINT_BRANCH_TAKEN = 0x3E,
    IP_REX = 0x40,
    IP_OPERAND_SIZE_OVERRIDE = 0x66,
    IP_ADDRESS_SIZE_OVERRIDE = 0x67,
    IP_LOCK = 0xF0,
    IP_REP_NE = 0xF2,
    IP_REP = 0xF3,
};

std::array<CPU::OpCode, 256> CPU::s_opcodes = {
// 00-0F
    &CPU::op_rm8_r8<OpAdd>,   // 0x00 ADD r/m8, r8
    &CPU::op_rm32_r32<OpAdd>, // 0x01 ADD r/m32, r32
    &CPU::op_r8_rm8<OpAdd>,   // 0x02 ADD r8, r/m8
    &CPU::op_r32_rm32<OpAdd>, // 0x03 ADD r32, r/m32
    &CPU::op_al_imm8<OpAdd>,  // 0x04 ADD AL, imm8
    &CPU::op_eax_imm32<OpAdd>,// 0x05 ADD EAX, imm32
    0,
    0,
    &CPU::op_rm8_r8<OpOr>,   // 0x08 OR r/m8, r8
    &CPU::op_rm32_r32<OpOr>, // 0x09 OR r/m32, r32
    &CPU::op_r8_rm8<OpOr>,   // 0x0A OR r8, r/m8
    &CPU::op_r32_rm32<OpOr>, // 0x0B OR r32, r/m32
    &CPU::op_al_imm8<OpOr>,  // 0x0C OR AL, imm8
    &CPU::op_eax_imm32<OpOr>,// 0x0D OR EAX, imm32
    0,
    0, // 2-byte opcode escape code
// 10-1F
    &CPU::op_rm8_r8<OpAdc>,   // 0x10 ADC r/m8, r8
    &CPU::op_rm32_r32<OpAdc>, // 0x11 ADC r/m8, r8
    &CPU::op_r8_rm8<OpAdc>,   // 0x12 ADC r8, r/m8
    &CPU::op_r32_rm32<OpAdc>, // 0x13 ADC r8, r/m8
    &CPU::op_al_imm8<OpAdc>,   // 0x14 ADC AL, imm8
    &CPU::op_eax_imm32<OpAdc>, // 0x15 ADC EAX, imm32
    0,
    0,
    &CPU::op_rm8_r8<OpSbb>,   // 0x18 SBB r/m8, r8
    &CPU::op_rm32_r32<OpSbb>, // 0x19 SBB r/m32, r32
    &CPU::op_r8_rm8<OpSbb>,   // 0x1A SBB r8, r/m8
    &CPU::op_r32_rm32<OpSbb>, // 0x1B SBB r32, r/m32
    &CPU::op_al_imm8<OpSbb>,  // 0x1C SBB AL, imm8
    &CPU::op_eax_imm32<OpSbb>,// 0x1D SBB EAX, imm32
    0,
    0,
// 20-2F
    &CPU::op_rm8_r8<OpAnd>,   // 0x20 AND r/m8, r8
    &CPU::op_rm32_r32<OpAnd>, // 0x21 AND r/m32, r32
    &CPU::op_r8_rm8<OpAnd>,   // 0x22 AND r8, r/m8
    &CPU::op_r32_rm32<OpAnd>, // 0x23 AND r8, r/m8
    &CPU::op_al_imm8<OpAnd>,  // 0x24 AND AL, imm8
    &CPU::op_eax_imm32<OpAnd>,// 0x25 AND EAX, imm32
    0,
    0,
    &CPU::op_rm8_r8<OpSub>,   // 0x28 SUB r/m8, r8
    &CPU::op_rm32_r32<OpSub>, // 0x29 SUB r/m32, r32
    &CPU::op_r8_rm8<OpSub>,   // 0x2A SUB r8, r/m8
    &CPU::op_r32_rm32<OpSub>, // 0x2B SUB r32, r/m32
    &CPU::op_al_imm8<OpSub>,   // 0x2C SUB AL, imm8
    &CPU::op_eax_imm32<OpSub>, // 0x2D SUB EAX, imm32
    { &CPU::decode_prefix<0x2E>, true }, // 0x2E Branch hint
    0,
// 30-3F
    &CPU::op_rm8_r8<OpXor>,   // 0x30 XOR r/m8, r8
    &CPU::op_rm32_r32<OpXor>, // 0x31 XOR r/m32, r32
    &CPU::op_r8_rm8<OpXor>,   // 0x32 XOR r8, r/m8
    &CPU::op_r32_rm32<OpXor>, // 0x33 XOR r32, r/m32
    &CPU::op_al_imm8<OpXor>,  // 0x34 XOR AL, imm8
    &CPU::op_eax_imm32<OpXor>,// 0x35 XOR EAX, imm32
    0,
    0,
    &CPU::op_rm8_r8<OpCmp>,   // 0x38 CMP r/m8, r8
    &CPU::op_rm32_r32<OpCmp>, // 0x39 CMP r/m32, r32
    &CPU::op_r8_rm8<OpCmp>,   // 0x3A CMP r8, r/m8
    &CPU::op_r32_rm32<OpCmp>, // 0x3B CMP r32, r/m32
    &CPU::op_al_imm8<OpCmp>,  // 0x3C CMP AL, imm8
    &CPU::op_eax_imm32<OpCmp>,// 0x3D CMP EAX, imm32
    { &CPU::decode_prefix<0x3E>, true }, // 0x3E Branch hint
    0,
// 40-4F
    { &CPU::decode_prefix<0x40>, true },
    { &CPU::decode_prefix<0x40>, true },
    { &CPU::decode_prefix<0x40>, true },
    { &CPU::decode_prefix<0x40>, true },
    { &CPU::decode_prefix<0x40>, true },
    { &CPU::decode_prefix<0x40>, true },
    { &CPU::decode_prefix<0x40>, true },
    { &CPU::decode_prefix<0x40>, true },
    { &CPU::decode_prefix<0x40>, true },
    { &CPU::decode_prefix<0x40>, true },
    { &CPU::decode_prefix<0x40>, true },
    { &CPU::decode_prefix<0x40>, true },
    { &CPU::decode_prefix<0x40>, true },
    { &CPU::decode_prefix<0x40>, true },
    { &CPU::decode_prefix<0x40>, true },
    { &CPU::decode_prefix<0x40>, true },
// 50-5F
    &CPU::execute_PUSH_50, // 0x50 PUSH RAX
    &CPU::execute_PUSH_50, // 0x51 PUSH
    &CPU::execute_PUSH_50, // 0x52 PUSH
    &CPU::execute_PUSH_50, // 0x53 PUSH
    &CPU::execute_PUSH_50, // 0x54 PUSH
    &CPU::execute_PUSH_50, // 0x55 PUSH
    &CPU::execute_PUSH_50, // 0x56 PUSH
    &CPU::execute_PUSH_50, // 0x57 PUSH
    &CPU::execute_POP_58, // 0x58 POP RAX
    &CPU::execute_POP_58, // 0x59 POP
    &CPU::execute_POP_58, // 0x5A POP
    &CPU::execute_POP_58, // 0x5B POP
    &CPU::execute_POP_58, // 0x5C POP
    &CPU::execute_POP_58, // 0x5D POP
    &CPU::execute_POP_58, // 0x5E POP
    &CPU::execute_POP_58, // 0x5F POP
// 60-6F
    0,
    0,
    0,
    0,
    0,
    0,
    { &CPU::decode_prefix<0x66>, true },
    { &CPU::decode_prefix<0x67>, true },
    &CPU::execute_PUSH_imm32, // 0x68 PUSH imm32
    0,
    &CPU::execute_PUSH_imm8,  // 0x6A PUSH imm8
    0,
    0,
    0,
    0,
    0,
// 70-7F
    &CPU::op_jmp_cond<CondO>,  // 0x70 JO rel8
    &CPU::op_jmp_cond<CondNO>, // 0x71 JNO rel8
    &CPU::op_jmp_cond<CondC>,  // 0x72 JB rel8
    &CPU::op_jmp_cond<CondNC>, // 0x73 JNB rel8
    &CPU::op_jmp_cond<CondZ>,  // 0x75 JZ rel8
    &CPU::op_jmp_cond<CondNZ>, // 0x75 JNZ rel8
    &CPU::op_jmp_cond<CondBE>, // 0x76 JBE rel8
    &CPU::op_jmp_cond<CondA>,  // 0x77 JA rel8
    &CPU::op_jmp_cond<CondS>,  // 0x78 JS rel8
    &CPU::op_jmp_cond<CondNS>, // 0x79 JNS rel8
    &CPU::op_jmp_cond<CondP>,  // 0x7A JP rel8
    &CPU::op_jmp_cond<CondNP>, // 0x7B JNP rel8
    &CPU::op_jmp_cond<CondL>,  // 0x7C JL rel8
    &CPU::op_jmp_cond<CondGE>, // 0x7D JGE rel8
    &CPU::op_jmp_cond<CondLE>, // 0x7E JLE rel8
    &CPU::op_jmp_cond<CondG>,  // 0x7F JLE rel8
// 80-8F
    &CPU::dispatch_rm8_imm8<OpAdd, OpOr, OpAdc, OpSbb, OpAnd, OpSub, OpXor, OpCmp>,  // 0x80 OP r/m8, imm8
    &CPU::dispatch_rm32_imm32<OpAdd, OpOr, OpAdc, OpSbb, OpAnd, OpSub, OpXor, OpCmp>,  // 0x81 OP r/m32, imm32
    0,
    &CPU::dispatch_rm32_imm8_sx<OpAdd, OpOr, OpAdc, OpSbb, OpAnd, OpSub, OpXor, OpCmp>,  // 0x83 OP r/m8, imm8 (sign-extended)
    &CPU::op_rm8_r8<OpTest>,   // 0x84 TEST r/m8, r8
    &CPU::op_rm32_r32<OpTest>, // 0x85 TEST r/m8, r8
    0,
    0,
    &CPU::op_rm8_r8<OpMov>,   // 0x88 MOV r/m8, r8
    &CPU::op_rm32_r32<OpMov>, // 0x89 MOV r/m32, r32
    &CPU::op_r8_rm8<OpMov>,   // 0x8A MOV r8, r/m8
    &CPU::op_r32_rm32<OpMov>, // 0x8B MOV r32, r/m32
    0,
    &CPU::execute_LEA,        // 0x8D LEA reg, [m]
    0,
    0,
// 90-9F
    &CPU::execute_NOP, // 0x90 NOP
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
// A0-AF
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    &CPU::op_al_imm8<OpTest>,   // 0xA8 TEST AL, imm8
    &CPU::op_eax_imm32<OpTest>, // 0xA9 TEST EAX, imm32
    0,
    0,
    0,
    0,
    0,
    0,
// B0-BF
    &CPU::execute_MOV_B0, &CPU::execute_MOV_B0, &CPU::execute_MOV_B0, &CPU::execute_MOV_B0, &CPU::execute_MOV_B0, &CPU::execute_MOV_B0, &CPU::execute_MOV_B0, &CPU::execute_MOV_B0,
    &CPU::execute_MOV_B8, &CPU::execute_MOV_B8, &CPU::execute_MOV_B8, &CPU::execute_MOV_B8, &CPU::execute_MOV_B8, &CPU::execute_MOV_B8, &CPU::execute_MOV_B8, &CPU::execute_MOV_B8,
// C0-CF
    0,
    0,
    &CPU::execute_RET_imm16_near, // 0xC2 RET imm16
    &CPU::execute_RET_near,       // 0xC3 RET
    0,
    0,
    0,
    0,
    &CPU::execute_ENTER, // 0xC8 ENTER
    &CPU::execute_LEAVE, // 0xC9 LEAVE
    &CPU::execute_RET_imm16_far, // 0xCA RET imm16
    &CPU::execute_RET_far,  // 0xCB RET
    &CPU::execute_INT_N<3>, // 0xCC INT 3
    &CPU::execute_INT_imm8, // 0xCD INT imm8
    0,
    0,
// D0-DF
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
// E0-EF
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    &CPU::execute_CALL,   // E8 CALL rel32
    &CPU::execute_JMP32,  // E9 JMP rel32
    0,
    &CPU::execute_JMP8, // EB JMP rel8
    0,
    0,
    0,
    0,
// F0-FF
    { &CPU::decode_prefix<0xF0>, true },
    &CPU::execute_INT_N<1>, // 0xF1 INT 1
    { &CPU::decode_prefix<0xF2>, true },
    { &CPU::decode_prefix<0xF3>, true },
    &CPU::execute_HLT_F4,
    &CPU::op_complement_flag<FLAG_CF>, // 0xF5 CMC
    &CPU::dispatch_F6, //OpTest, OpNop, OpNot, OpNeg, OpMul, OpIMul, OpDiv, OpIDiv, // 0xF6 /x
    &CPU::dispatch_F7, //OpTest, OpNop, OpNot, OpNeg, OpMul, OpIMul, OpDiv, OpIDiv, // 0xF6 /x
    &CPU::op_clear_flag<FLAG_CF>, // 0xF8 CLC
    &CPU::op_set_flag<FLAG_CF>,   // 0xF9 STC
    &CPU::op_clear_flag<FLAG_IF>, // 0xFA CLI
    &CPU::op_set_flag<FLAG_IF>,   // 0xFB STI
    &CPU::op_clear_flag<FLAG_DF>, // 0xFC CLD
    &CPU::op_set_flag<FLAG_DF>,   // 0xFD STD
    0,
    0,
};

std::array<CPU::OpCode, 256> CPU::s_opcodes2 = {
// 00-0F
    0,
    0,
    0,
    0,
    0,
    &CPU::execute_SYSCALL, // 0F 05 SYSCALL
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
// 10-1F
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
// 20-2F
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
// 30-3F
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
// 40-4F
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
// 50-5F
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
// 60-6F
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
// 70-7F
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
// 80-8F
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
// 90-9F
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
// A0-AF
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
// B0-BF
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
// C0-CF
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
// D0-DF
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
// E0-EF
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
// F0-FF
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
};

CPU::CPU(kernel::IfKernel64* kernel)
: m_kernel(kernel)
{
    m_registers.fill(0);
    m_segment_registers.fill(0);
}

const std::uint8_t* CPU::translate_instruction_address(ptr_t address)
{
    auto p = reinterpret_cast<const std::uint8_t*>(static_cast<const kernel::IfKernel64*>(m_kernel)->translate_address(address));
    m_ip_address_offset = reinterpret_cast<uintptr_t>(p) - address;
    return p;
}

const std::uint8_t* CPU::get_instruction_address(ptr_t address) const
{
    return reinterpret_cast<const std::uint8_t*>(address + m_ip_address_offset);
}

uint8_t& CPU::reg8(uint8_t reg, bool with_rex, bool extension)
{
    assert(reg < 8);
    if (with_rex)
    {
        // enable access to SIL/DIL/BPL/SPL when rex_enabled
        return reinterpret_cast<uint8_t*>(&m_registers[reg | (extension << 3)])[0];
    }
    else
    {
        return reinterpret_cast<uint8_t*>(&m_registers[reg & 3])[(reg & 4) == 4];
    }
}

uint16_t& CPU::reg16(uint8_t reg)
{
    assert(reg < 8);
    return reinterpret_cast<uint16_t&>(m_registers[reg]);
}

uint32_t& CPU::reg32(uint8_t reg)
{
    assert(reg < 8);
    return reinterpret_cast<uint32_t&>(m_registers[reg]);
}

uint64_t& CPU::reg64(uint8_t reg, bool extension)
{
    assert(reg < 8);
    return m_registers[reg | (extension << 3)];
}

template<typename T>
void CPU::store(ptr_t address, T value)
{
    *reinterpret_cast<T*>(m_kernel->translate_address(address)) = value;
}

template<typename T>
T CPU::load(ptr_t address) const
{
    return *reinterpret_cast<const T*>(static_cast<const kernel::IfKernel64*>(m_kernel)->translate_address(address));
}

template<typename T>
void CPU::stack_push(T value)
{
    auto& rsp = m_registers[REG_RSP];
    rsp -= sizeof(T);
    store(rsp, value);
}

template<typename T>
T CPU::stack_pop()
{
    auto& rsp = m_registers[REG_RSP];
    T value = load<T>(rsp);
    rsp += sizeof(T);
    return value;
}

template<typename Op, typename T>
void CPU::op_r(T& first, cpu::X86_64::flag_t& flags)
{
    auto result = Op::call(first, flags);
    if constexpr (Op::STORE_RESULT)
    {
        first = result;
    }
}

template<typename Op, typename T>
void CPU::op_r_r(T& first, T second, cpu::X86_64::flag_t& flags)
{
    auto result = Op::call(first, second, flags);
    if constexpr (Op::STORE_RESULT)
    {
        first = result;
    }
}

template<typename Op, typename T>
void CPU::op_m(ptr_t first_addr, cpu::X86_64::flag_t& flags)
{
    T first;
    if constexpr (Op::LOAD_FIRST)
    {
        first = load<T>(first_addr);
    }
    first = Op::call(first, flags);
    if constexpr (Op::STORE_RESULT)
    {
        store(first_addr, first);
    }
}

template<typename Op, typename T>
void CPU::op_m_r(ptr_t first_addr, T second, cpu::X86_64::flag_t& flags)
{
    T first;
    if constexpr (Op::LOAD_FIRST)
    {
        first = load<T>(first_addr);
    }
    first = Op::call(first, second, flags);
    if constexpr (Op::STORE_RESULT)
    {
        store(first_addr, first);
    }
}

template<uint8_t code>
ptr_t CPU::decode_prefix(Instruction& instruction, ptr_t ip)
{
    if constexpr (code == IP_HINT_BRANCH_NOT_TAKEN)
    {
        // ignore hint
    }
    else if constexpr (code == IP_HINT_BRANCH_NOT_TAKEN)
    {
        // ignore hint
    }
    else if constexpr (code == IP_ADDRESS_SIZE_OVERRIDE)
    {
        instruction.address_size_override = true;
    }
    else if constexpr (code == IP_OPERAND_SIZE_OVERRIDE)
    {
        instruction.operand_size_override = true;
    }
    else if constexpr (code == IP_LOCK)
    {
        instruction.lock = true;
    }
    else if constexpr (code == IP_REP_NE)
    {
        instruction.rep_ne = true;
    }
    else if constexpr (code == IP_REP)
    {
        instruction.rep = true;
    }
    else if constexpr (code == IP_REX)
    {
        instruction.rex = instruction.opcode;
    }
    else
    {
        assert(false);
    }

    return ip + 1;
}

ptr_t CPU::execute_one(ptr_t ip)
{
    const std::uint8_t* op = translate_instruction_address(ip);
    if (!op)
    {
        throw std::runtime_error("illegal instruction address");
    }

    // decode the instruction
    Instruction instruction = {0};
    while (true)
    {
        uint8_t code = op[0];
        OpCode* executor;
        if (code == 0x0F) //escape code
        {
            code = op[1];
            executor = &s_opcodes2[code];
            instruction.escape = true;
            ++ip;
        }
        else
        {
            executor = &s_opcodes[code];
        }
        
        if (!executor->f)
        {
            throw std::runtime_error("unsupported instruction");
        }
        instruction.opcode = code;
        auto next_ip = (this->*(executor->f))(instruction, ip);
        if (!executor->prefix)
        {
            return next_ip;
        }

        op += (next_ip - ip);
        ip = next_ip;
    }
}

void CPU::execute_next()
{
    m_ip = execute_one(m_ip);
}

template<bool modrm, int imm_size>
ptr_t CPU::decode_instruction(Instruction& inst, ptr_t ip)
{
    auto p = get_instruction_address(ip);
    size_t length = 1;

    if constexpr (modrm)
    {
        auto mod_rm = *reinterpret_cast<const ModRM*>(p + length);
        ++length;
        inst.mod_rm = mod_rm;
        if (mod_rm.mod != MOD_DIRECT_REGISTER)
        {
            int32_t address = 0;
            if (mod_rm.rm == 0x4)
            {
                const auto sib = *reinterpret_cast<const SIB*>(p + length);
                ++length;
                switch (mod_rm.mod)
                {
                case MOD_INDIRECT_8BIT:
                    address = *reinterpret_cast<const int8_t*>(p + length);
                    ++length;
                    break;
                case MOD_INDIRECT_32BIT:
                    address = *reinterpret_cast<const int32_t*>(p + length);
                    length+=4;
                    break;
                }
                address += reg64(sib.base, inst.rex_b);
                if (sib.index != 0x04)
                {
                    address += reg64(sib.index, inst.rex_x) << sib.scale;
                }
                inst.address = address;
            }
            else if (mod_rm.rm == 5 && mod_rm.mod == 0)
            {
                // disp32
                // TODO: it is unclear if that values needs to be added to something, different assembler make different op-codes
                throw std::runtime_error("implementation uncertain");
            }
            else
            {
                switch (mod_rm.mod)
                {
                case MOD_INDIRECT_8BIT:
                    address = *reinterpret_cast<const int8_t*>(p + length);
                    ++length;
                    break;
                case MOD_INDIRECT_32BIT:
                    address = *reinterpret_cast<const int32_t*>(p + length);
                    length += 4;
                    break;
                }
                inst.address = reg64(mod_rm.rm, inst.rex_b) + address;
            }
        }
    }

    if constexpr (imm_size == 0)
    {
        // do not read imm
    }
    else if constexpr (imm_size == 1)
    {
        inst.imm = *reinterpret_cast<const int8_t*>(p + length);
        ++length;
    }
    else if constexpr (imm_size == 2)
    {
        inst.imm = *reinterpret_cast<const int16_t*>(p + length);
        length += 2;
    }
    else
    {
        if (inst.operand_size_override)
        {
            inst.imm = *reinterpret_cast<const int16_t*>(p + length);
            length += 2;
        }
        else
        {
            inst.imm = *reinterpret_cast<const int32_t*>(p + length);
            length += 4;
        }
    }
    return ip + length;
}

template<typename Op>
ptr_t CPU::op_al_imm8(Instruction& inst, ptr_t ip)
{
    flag_t flags = 0;
    if constexpr (Op::AFFECTED_FLAGS)
    {
        flags = m_flags;
    }
    ip = decode_instruction<false, 1>(inst, ip);
    op_r_r<Op>(reg8(REG_RAX, false, false), static_cast<uint8_t>(inst.imm), flags);
    if constexpr (Op::AFFECTED_FLAGS)
    {
        m_flags = flags;
    }
    return ip;
}

template<typename Op>
ptr_t CPU::op_eax_imm32(Instruction& inst, ptr_t ip)
{
    flag_t flags = 0;
    if constexpr (Op::AFFECTED_FLAGS)
    {
        flags = m_flags;
    }
    ip = decode_instruction<false, 4>(inst, ip);
    if (inst.operand_size_override)
    {
        op_r_r<Op>(reg16(REG_RAX), static_cast<uint16_t>(inst.imm), flags);
    }
    else
    {
        if (inst.rex_w)
        {
            uint64_t imm64 = static_cast<int64_t>(inst.imm);
            op_r_r<Op>(reg64(REG_RAX, inst.rex_b), imm64, flags);
        }
        else
        {
            op_r_r<Op>(reg32(REG_RAX), static_cast<uint32_t>(inst.imm), flags);
        }
    }
    if constexpr (Op::AFFECTED_FLAGS)
    {
        m_flags = flags;
    }
    return ip;
}

template<typename Cond>
ptr_t CPU::op_jmp_cond(Instruction& instruction, ptr_t ip)
{
    if (Cond::test(m_flags))
    {
        ip = decode_instruction<false, 1>(instruction, ip);
        return ip + instruction.imm;
    }
    return ip + 2;
}

template<typename Op>
ptr_t CPU::op_rm8(Instruction& inst, ptr_t ip)
{
    flag_t flags = 0;
    if constexpr (Op::AFFECTED_FLAGS)
    {
        flags = m_flags;
    }
    // modrm has already been decoded
    const ModRM modrm = inst.mod_rm;
    if (modrm.mod == MOD_DIRECT_REGISTER)
    {
        op_r<Op>(reg8(modrm.rm, inst.rex != 0, inst.rex_b), flags);
    }
    else
    {
        op_m<Op, uint8_t>(inst.address, flags);
    }
    if constexpr (Op::AFFECTED_FLAGS)
    {
        m_flags = flags;
    }
    return ip;
}

template<typename Op>
ptr_t CPU::op_rm8_imm8(Instruction& inst, ptr_t ip)
{
    flag_t flags = 0;
    if constexpr (Op::AFFECTED_FLAGS)
    {
        flags = m_flags;
    }
    // modrm has already been decoded
    auto p = get_instruction_address(ip);
    uint8_t imm = p[0];
    const ModRM modrm = inst.mod_rm;
    if (modrm.mod == MOD_DIRECT_REGISTER)
    {
        op_r_r<Op>(reg8(modrm.rm, inst.rex != 0, inst.rex_b), imm, flags);
    }
    else
    {
        op_m_r<Op>(inst.address, imm, flags);
    }
    if constexpr (Op::AFFECTED_FLAGS)
    {
        m_flags = flags;
    }
    return ip + 1;
}

template<typename Op>
ptr_t CPU::op_rm8_r8(Instruction& inst, ptr_t ip)
{
    flag_t flags = 0;
    if constexpr (Op::AFFECTED_FLAGS)
    {
        flags = m_flags;
    }
    ip = decode_instruction<true>(inst, ip);
    const ModRM modrm = inst.mod_rm;
    const uint8_t reg = reg8(modrm.reg, inst.rex != 0, inst.rex_r);
    if (modrm.mod == MOD_DIRECT_REGISTER)
    {
        op_r_r<Op>(reg8(modrm.rm, inst.rex != 0, inst.rex_b), reg, flags);
    }
    else
    {
        op_m_r<Op>(inst.address, reg, flags);
    }
    if constexpr (Op::AFFECTED_FLAGS)
    {
        m_flags = flags;
    }
    return ip;
}

template<typename Op0, typename Op1, typename Op2, typename Op3, typename Op4, typename Op5, typename Op6, typename Op7>
ptr_t CPU::dispatch_rm8_imm8(Instruction& inst, ptr_t ip)
{
    ip = decode_instruction<true, 1>(inst, ip);
    flag_t flags = m_flags;
    const ModRM modrm = inst.mod_rm;
    auto imm8 = static_cast<uint8_t>(inst.imm);
    if (modrm.mod == MOD_DIRECT_REGISTER)
    {
        auto& dst = reg8(modrm.rm, inst.rex != 0, inst.rex_b);
        switch (modrm.reg)
        {
        case 0:
            op_r_r<Op0>(dst, imm8, flags);
            break;
        case 1:
            op_r_r<Op1>(dst, imm8, flags);
            break;
        case 2:
            op_r_r<Op2>(dst, imm8, flags);
            break;
        case 3:
            op_r_r<Op3>(dst, imm8, flags);
            break;
        case 4:
            op_r_r<Op4>(dst, imm8, flags);
            break;
        case 5:
            op_r_r<Op5>(dst, imm8, flags);
            break;
        case 6:
            op_r_r<Op6>(dst, imm8, flags);
            break;
        case 7:
            op_r_r<Op7>(dst, imm8, flags);
            break;
        }
    }
    else
    {
        switch (modrm.reg)
        {
        case 0:
            op_m_r<Op0>(inst.address, imm8, flags);
            break;
        case 1:
            op_m_r<Op1>(inst.address, imm8, flags);
            break;
        case 2:
            op_m_r<Op2>(inst.address, imm8, flags);
            break;
        case 3:
            op_m_r<Op3>(inst.address, imm8, flags);
            break;
        case 4:
            op_m_r<Op4>(inst.address, imm8, flags);
            break;
        case 5:
            op_m_r<Op5>(inst.address, imm8, flags);
            break;
        case 6:
            op_m_r<Op6>(inst.address, imm8, flags);
            break;
        case 7:
            op_m_r<Op7>(inst.address, imm8, flags);
            break;
        }
    }
    m_flags = flags;
    return ip;
}

template<typename Op0, typename Op1, typename Op2, typename Op3, typename Op4, typename Op5, typename Op6, typename Op7>
ptr_t CPU::dispatch_rm32_imm32(Instruction& inst, ptr_t ip)
{
    ip = decode_instruction<true, 4>(inst, ip);
    flag_t flags = m_flags;

    throw std::runtime_error("Not implemented");

    m_flags = flags;
    return ip;
}

template<typename Op0, typename Op1, typename Op2, typename Op3, typename Op4, typename Op5, typename Op6, typename Op7>
ptr_t CPU::dispatch_rm32_imm8_sx(Instruction& inst, ptr_t ip)
{
    ip = decode_instruction<true, 1>(inst, ip);
    flag_t flags = m_flags;

    throw std::runtime_error("Not implemented");

    m_flags = flags;
    return ip;
}

template<typename Op>
ptr_t CPU::op_rm32(Instruction& inst, ptr_t ip)
{
    flag_t flags = 0;
    if constexpr (Op::AFFECTED_FLAGS)
    {
        flags = m_flags;
    }
    const ModRM modrm = inst.mod_rm;
    if (modrm.mod == MOD_DIRECT_REGISTER)
    {
        if (inst.operand_size_override)
        {
            op_r<Op>(reg16(modrm.rm), flags);
        }
        else if (inst.rex_w)
        {
            op_r<Op>(reg64(modrm.rm, inst.rex_b), flags);
        }
        else
        {
            op_r<Op>(reg32(modrm.rm), flags);
        }
    }
    else
    {
        if (inst.operand_size_override)
        {
            op_m<Op, uint16_t>(inst.address, flags);
        }
        else if (inst.rex_w)
        {
            op_m<Op, uint64_t>(inst.address, flags);
        }
        else
        {
            op_m<Op, uint32_t>(inst.address, flags);
        }
    }
    if constexpr (Op::AFFECTED_FLAGS)
    {
        m_flags = flags;
    }
    return ip;
}

template<typename Op>
ptr_t CPU::op_rm32_imm32(Instruction& inst, ptr_t ip)
{
    flag_t flags = 0;
    if constexpr (Op::AFFECTED_FLAGS)
    {
        flags = m_flags;
    }
    // mod_rm has already been decoded
    auto p = get_instruction_address(ip);
    const ModRM modrm = inst.mod_rm;
    if (modrm.mod == MOD_DIRECT_REGISTER)
    {
        if (inst.operand_size_override)
        {
            auto imm = *reinterpret_cast<const uint16_t*>(p);
            ip += sizeof(imm);
            op_r_r<Op>(reg16(modrm.rm), imm, flags);
        }
        else if (inst.rex_w)
        {
            auto imm = *reinterpret_cast<const uint64_t*>(p);
            ip += sizeof(imm);
            op_r_r<Op>(reg64(modrm.rm, inst.rex_b), imm, flags);
        }
        else
        {
            auto imm = *reinterpret_cast<const uint32_t*>(p);
            ip += sizeof(imm);
            op_r_r<Op>(reg32(modrm.rm), imm, flags);
        }
    }
    else
    {
        if (inst.operand_size_override)
        {
            auto imm = *reinterpret_cast<const uint16_t*>(p);
            ip += sizeof(imm);
            op_m_r<Op>(inst.address, imm, flags);
        }
        else if (inst.rex_w)
        {
            auto imm = *reinterpret_cast<const uint64_t*>(p);
            ip += sizeof(imm);
            op_m_r<Op>(inst.address, imm, flags);
        }
        else
        {
            auto imm = *reinterpret_cast<const uint32_t*>(p);
            ip += sizeof(imm);
            op_m_r<Op>(inst.address, imm, flags);
        }
    }
    if constexpr (Op::AFFECTED_FLAGS)
    {
        m_flags = flags;
    }
    return ip;
}

template<typename Op>
ptr_t CPU::op_rm32_r32(Instruction& inst, ptr_t ip)
{
    flag_t flags = 0;
    if constexpr (Op::AFFECTED_FLAGS)
    {
        flags = m_flags;
    }
    ip = decode_instruction<true>(inst, ip);
    const ModRM modrm = inst.mod_rm;
    if (modrm.mod == MOD_DIRECT_REGISTER)
    {
        if (inst.operand_size_override)
        {
            op_r_r<Op>(reg16(modrm.rm), reg16(modrm.reg), flags);
        }
        else if (inst.rex_w)
        {
            op_r_r<Op>(reg64(modrm.rm, inst.rex_b), reg64(modrm.reg, inst.rex_r), flags);
        }
        else
        {
            op_r_r<Op>(reg32(modrm.rm), reg32(modrm.reg), flags);
        }
    }
    else
    {
        if (inst.operand_size_override)
        {
            op_m_r<Op>(inst.address, reg16(modrm.reg), flags);
        }
        else if (inst.rex_w)
        {
            op_m_r<Op>(inst.address, reg64(modrm.reg, inst.rex_r), flags);
        }
        else
        {
            op_m_r<Op>(inst.address, reg32(modrm.reg), flags);
        }
    }
    if constexpr (Op::AFFECTED_FLAGS)
    {
        m_flags = flags;
    }
    return ip;
}

template<typename Op>
ptr_t CPU::op_r8_rm8(Instruction& inst, ptr_t ip)
{
    flag_t flags = 0;
    if constexpr (Op::AFFECTED_FLAGS)
    {
        flags = m_flags;
    }
    ip = decode_instruction<true>(inst, ip);
    const ModRM modrm = inst.mod_rm;
    uint8_t& dst = reg8(modrm.reg, inst.rex != 0, inst.rex_r);
    if (modrm.mod == MOD_DIRECT_REGISTER)
    {
        uint8_t reg = reg8(modrm.rm, inst.rex != 0, inst.rex_b);
        op_r_r<Op>(dst, reg, flags);
    }
    else
    {
        uint8_t val = load<uint8_t>(inst.address);
        op_r_r<Op>(dst, val, flags);
    }
    if constexpr (Op::AFFECTED_FLAGS)
    {
        m_flags = flags;
    }
    return ip;
}

template<typename Op>
ptr_t CPU::op_r32_rm32(Instruction& inst, ptr_t ip)
{
    flag_t flags = 0;
    if constexpr (Op::AFFECTED_FLAGS)
    {
        flags = m_flags;
    }
    ip = decode_instruction<true>(inst, ip);
    const ModRM modrm = inst.mod_rm;
    if (modrm.mod == MOD_DIRECT_REGISTER)
    {
        if (inst.operand_size_override)
        {
            op_r_r<Op>(reg16(modrm.reg), reg16(modrm.rm), flags);
        }
        else if (inst.rex_w)
        {
            op_r_r<Op>(reg64(modrm.reg, inst.rex_r), reg64(modrm.rm, inst.rex_b), flags);
        }
        else
        {
            op_r_r<Op>(reg32(modrm.reg), reg32(modrm.rm), flags);
        }
    }
    else
    {
        if (inst.operand_size_override)
        {
            op_r_r<Op>(reg16(modrm.reg), load<uint16_t>(inst.address), flags);
        }
        else if (inst.rex_w)
        {
            op_r_r<Op>(reg64(modrm.reg, inst.rex_r), load<uint64_t>(inst.address), flags);
        }
        else
        {
            op_r_r<Op>(reg32(modrm.reg), load<uint32_t>(inst.address), flags);
        }
    }
    if constexpr (Op::AFFECTED_FLAGS)
    {
        m_flags = flags;
    }
    return ip;
}

ptr_t CPU::dispatch_F6(Instruction& inst, ptr_t ip)
{
    ip = decode_instruction<true, 0>(inst, ip);
    switch (inst.mod_rm.reg)
    {
    case 0:
        return op_rm8_imm8<OpTest>(inst, ip);
    case 2:
        return op_rm8<OpNot>(inst, ip);
    case 3:
        return op_rm8<OpNeg>(inst, ip);
    default:
        throw std::runtime_error("Unsupported instruction");
    }
}

ptr_t CPU::dispatch_F7(Instruction& inst, ptr_t ip)
{
    ip = decode_instruction<true, 0>(inst, ip);
    switch (inst.mod_rm.reg)
    {
    case 0:
        return op_rm32_imm32<OpTest>(inst, ip);
    case 2:
        return op_rm32<OpNot>(inst, ip);
    case 3:
        return op_rm32<OpNeg>(inst, ip);
    default:
        throw std::runtime_error("Unsupported instruction");
    }
}

ptr_t CPU::execute_CALL(Instruction& inst, ptr_t ip)
{
    ip = decode_instruction<false, 4>(inst, ip);
    stack_push(ip);
    return ip + inst.imm;
}

ptr_t CPU::execute_RET_near(Instruction&, ptr_t)
{
    return stack_pop<ptr_t>();
}

ptr_t CPU::execute_RET_far(Instruction& inst, ptr_t ip)
{
    throw std::runtime_error("Far return not implemented");
}

ptr_t CPU::execute_RET_imm16_near(Instruction& inst, ptr_t ip)
{
    decode_instruction<false, 2>(inst, ip);
    auto rsp = getRegister(REG_RSP);
    setRegister(REG_RSP, rsp + sizeof(ptr_t) + inst.imm);
    return load<ptr_t>(rsp);
}

ptr_t CPU::execute_RET_imm16_far(Instruction&, ptr_t ip)
{
    throw std::runtime_error("Far return not implemented");
}

ptr_t CPU::execute_MOV_B0(Instruction& inst, ptr_t ip)
{
    ip = decode_instruction<false, 1>(inst, ip);
    reg8(inst.opcode & 0x07, inst.rex != 0, inst.rex_b) = static_cast<uint8_t>(inst.imm);
    return ip;
}

ptr_t CPU::execute_MOV_B8(Instruction& inst, ptr_t ip)
{
    auto p = get_instruction_address(ip);
    auto reg = p[0] & 0x07;
    if (inst.operand_size_override)
    {
        reg16(reg) = *reinterpret_cast<const std::uint16_t*>(p + 1);
        return ip + 3;
    }
    if (inst.rex_w)
    {
        reg64(reg, inst.rex_b) = *reinterpret_cast<const std::uint64_t*>(p + 1);
        return ip + 9;
    }

    reg32(reg) = *reinterpret_cast<const std::uint32_t*>(p + 1);
    return ip + 5;
}

ptr_t CPU::execute_NOP(Instruction&, ptr_t ip)
{
    return ip + 1;
}

ptr_t CPU::execute_JMP8(Instruction& instruction, ptr_t ip)
{
    ip = decode_instruction<false, 1>(instruction, ip);
    return ip + instruction.imm;
}

ptr_t CPU::execute_JMP32(Instruction& instruction, ptr_t ip)
{
    ip = decode_instruction<false, 4>(instruction, ip);
    return ip + instruction.imm;
}

ptr_t CPU::execute_ENTER(Instruction&, ptr_t ip)
{
    auto p = get_instruction_address(ip);
    int16_t imm16 = *reinterpret_cast<const int16_t*>(p + 1);
    int8_t level = p[3];
    if (level != 0)
    {
        throw std::runtime_error("No nested function support yet");
    }
    auto& rsp = m_registers[REG_RSP];
    auto& rbp = m_registers[REG_RBP];
    stack_push(rbp);
    rbp = rsp;
    rsp -= imm16;
    return ip + 4;
}

ptr_t CPU::execute_LEAVE(Instruction&, ptr_t ip)
{
    auto rsp = getRegister(REG_RBP);
    setRegister(REG_RBP, load<ptr_t>(rsp));
    setRegister(REG_RSP, rsp + sizeof(ptr_t));
    return ip + 1;
}

ptr_t CPU::execute_LEA(Instruction& inst, ptr_t ip)
{
    ip = decode_instruction<true>(inst, ip);
    if (inst.operand_size_override)
    {
        reg16(inst.mod_rm.reg) = inst.address;
    }
    else if (inst.rex_w)
    {
        reg64(inst.mod_rm.reg, inst.rex_r) = inst.address;
    }
    else
    {
        reg32(inst.mod_rm.reg) = inst.address_size_override ? static_cast<uint32_t>(inst.address) : inst.address;
    }
    return ip;
}

ptr_t CPU::execute_HLT_F4(Instruction& i, ptr_t ip) { return ip; } // TODO: maybe throw a HLT exception, but required privilege level 0

ptr_t CPU::execute_PUSH_imm8(Instruction& inst, ptr_t ip)
{
    ip = decode_instruction<false, 1>(inst, ip);
    stack_push(static_cast<uint8_t>(inst.imm));
    return ip;
}

ptr_t CPU::execute_PUSH_imm32(Instruction& inst, ptr_t ip)
{
    if (inst.operand_size_override)
    {
        ip = decode_instruction<false, sizeof(int16_t)>(inst, ip);
        stack_push(static_cast<int16_t>(inst.imm));
    }
    else
    {
        ip = decode_instruction<false, sizeof(int32_t)>(inst, ip);
        stack_push(inst.imm);
    }
    return ip;
}

ptr_t CPU::execute_PUSH_50(Instruction& inst, ptr_t ip)
{
    if (inst.operand_size_override)
    {
        stack_push(reg16(inst.opcode & 0x07));
    }
    else
    {
        stack_push(reg64(inst.opcode & 0x07, inst.rex_b));
    }
    return ip + 1;
}

ptr_t CPU::execute_POP_58(Instruction& inst, ptr_t ip)
{
    if (inst.operand_size_override)
    {
        reg16(inst.opcode & 0x07) = stack_pop<uint16_t>();
    }
    else
    {
        reg64(inst.opcode & 0x07, inst.rex_b) = stack_pop<uint64_t>();
    }
    return ip + 1;
}

template<uint8_t N>
ptr_t CPU::execute_INT_N(Instruction&, ptr_t ip)
{
    dispatch_int(N);
    return ip + 1;
}

ptr_t CPU::execute_INT_imm8(Instruction& instruction, ptr_t ip)
{
    ip = decode_instruction<false, 1>(instruction, ip);
    dispatch_int(static_cast<uint8_t>(instruction.imm));
    return ip;
}

template<cpu::X86_64::flag_t flag>
ptr_t CPU::op_clear_flag(Instruction&, ptr_t ip)
{
    m_flags &= ~flag;
    return ip + 1;
}

template<cpu::X86_64::flag_t flag>
ptr_t CPU::op_set_flag(Instruction&, ptr_t ip)
{
    m_flags |= flag;
    return ip + 1;
}

template<cpu::X86_64::flag_t flag>
ptr_t CPU::op_complement_flag(Instruction&, ptr_t ip)
{
    m_flags ^= flag;
    return ip + 1;
}

ptr_t CPU::execute_SYSCALL(Instruction&, ptr_t ip)
{
    dispatch_syscall(ip + 1);
    return ip + 1;
}

void CPU::dispatch_syscall(ptr_t next_ip)
{
    setRegister(REG_RCX, next_ip); /* Will contain address of next instruction */
    setRegister(REG_R11, m_flags);

    uint64_t ret = 0;
    if (m_kernel)
    {
        switch (m_kernel->getType())
        {
        case kernel::KernelType::None:
            break;

        case kernel::KernelType::Linux64:
        {
            // Linux x86_64 System Call
            auto number = getRegister(REG_RAX);
            uint64_t arg[6] = {
                getRegister(REG_RDI),
                getRegister(REG_RSI),
                getRegister(REG_RDX),
                getRegister(REG_R10),
                getRegister(REG_R8),
                getRegister(REG_R9),
            };
            ret = m_kernel->syscall(number, arg, 6);
            break;
        }
        default:
            throw std::runtime_error("Unsupported kernel");
        }
    }
    setRegister(REG_RAX, ret);
}

void CPU::dispatch_int(uint8_t interrupt)
{
    throw std::runtime_error("Not implemented");
}
