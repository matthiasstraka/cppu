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
    IP_REX = 0x40,
    IP_OPERAND_SIZE_OVERRIDE = 0x66,
    IP_ADDRESS_SIZE_OVERRIDE = 0x67,
    IP_LOCK = 0xF0,
    IP_REP_NE = 0xF2,
    IP_REP = 0xF3,
};

/**
 * see https://wiki.osdev.org/X86-64_Instruction_Encoding#REX_prefix
 */
enum Rex
{
    REX_B = 0x01,
    REX_X = 0x02,
    REX_R = 0x04,
    REX_W = 0x08,
};

std::array<CPU::OpCode, 256> CPU::s_opcodes = {
// 00-0F
    &CPU::op_rm8_r8<OpAdd>, // 0x00 ADD r/m8, r8
    0,
    0,
    0,
    &CPU::op_al_imm8<OpAdd>,
    &CPU::op_eax_imm32<OpAdd>,
    0,
    0,
    &CPU::op_rm8_r8<OpOr>, // 0x08 OR r/m8, r8
    0,
    0,
    0,
    &CPU::op_al_imm8<OpOr>,
    &CPU::op_eax_imm32<OpOr>,
    0,
    &CPU::execute_0F,
// 10-1F
    &CPU::op_rm8_r8<OpAdc>, // 0x10 ADC r/m8, r8
    0,
    0,
    0,
    &CPU::op_al_imm8<OpAdc>,   // 0x14 ADC AL, imm8
    &CPU::op_eax_imm32<OpAdc>, // 0x15 ADC EAX, imm32
    0,
    0,
    &CPU::op_rm8_r8<OpSbb>, // 0x18 SBB r/m8, r8
    0,
    0,
    0,
    &CPU::op_al_imm8<OpSbb>,   // 0x1C SBB AL, imm8
    &CPU::op_eax_imm32<OpSbb>, // 0x1D SBB EAX, imm32
    0,
    0,
// 20-2F
    &CPU::op_rm8_r8<OpAnd>, // 0x20 AND r/m8, r8
    0,
    0,
    0,
    &CPU::op_al_imm8<OpAnd>,
    &CPU::op_eax_imm32<OpAnd>,
    0,
    0,
    &CPU::op_rm8_r8<OpSub>, // 0x28 SUB r/m8, r8
    0,
    0,
    0,
    &CPU::op_al_imm8<OpSub>,   // 0x2C SUB AL, imm8
    &CPU::op_eax_imm32<OpSub>, // 0x1D SUB EAX, imm32
    0,
    0,
// 30-3F
    &CPU::op_rm8_r8<OpXor>, // 0x30 XOR r/m8, r8
    0,
    0,
    0,
    &CPU::op_al_imm8<OpXor>,
    &CPU::op_eax_imm32<OpXor>,
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
    { &CPU::decode_prefix<0x66>, true },
    { &CPU::decode_prefix<0x67>, true },
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
    &CPU::execute_Jcc_7x, // 71
    &CPU::execute_Jcc_7x, // 72
    &CPU::execute_Jcc_7x, // 73
    &CPU::execute_Jcc_7x, // 74
    &CPU::execute_Jcc_7x, // 75
    &CPU::execute_Jcc_7x, // 76
    &CPU::execute_Jcc_7x, // 77
    &CPU::execute_Jcc_7x, // 78
    &CPU::execute_Jcc_7x, // 79
    &CPU::execute_Jcc_7x, // 7A
    &CPU::execute_Jcc_7x, // 7B
    &CPU::execute_Jcc_7x, // 7C
    &CPU::execute_Jcc_7x, // 7D
    &CPU::execute_Jcc_7x, // 7E
    &CPU::execute_Jcc_7x, // 7F
// 80-8F
    0,
    0,
    0,
    0,
    &CPU::op_rm8_r8<OpTest>, // 0x84 TEST r/m8, r8
    0,
    0,
    0,
    &CPU::op_rm8_r8<OpMov>, // 0x88 MOV r/m8, r8
    &CPU::execute_MOV_89,
    &CPU::execute_MOV_8A,
    &CPU::execute_MOV_8B,
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
    &CPU::op_al_imm8<OpTest>, // 0xA8 TEST AL, imm8
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
    &CPU::execute_JMP, // E9
    0,
    &CPU::execute_JMP, // EB
    0,
    0,
    0,
    0,
// F0-FF
    { &CPU::decode_prefix<0xF0>, true },
    0,
    { &CPU::decode_prefix<0xF2>, true },
    { &CPU::decode_prefix<0xF3>, true },
    &CPU::execute_HLT_F4,
    &CPU::execute_CMC_F5,
    0,
    0,
    &CPU::execute_CLC_F8,
    &CPU::execute_STC_F9,
    &CPU::execute_CLI_FA,
    &CPU::execute_STI_FB,
    &CPU::execute_CLD_FC,
    &CPU::execute_STD_FD,
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

template<typename T>
const T& CPU::fetch_imm(ptr_t address) const
{
    return *reinterpret_cast<const T*>(address + m_ip_address_offset);
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
T CPU::load(ptr_t address)
{
    return *reinterpret_cast<const T*>(static_cast<const kernel::IfKernel64*>(m_kernel)->translate_address(address));
}

template<uint8_t code>
ptr_t CPU::decode_prefix(Instruction& instruction, ptr_t ip)
{
    if constexpr (code == IP_ADDRESS_SIZE_OVERRIDE)
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
        //instruction.rex_b = (rex & REX_B) == REX_B;
        //instruction.rex_x = (rex & REX_X) == REX_X;
        //instruction.rex_r = (rex & REX_R) == REX_R;
        //instruction.rex_w = (rex & REX_W) == REX_W;
        instruction.rex = *get_instruction_address(ip);
        instruction.rex_present = true;
    }
    else
    {
        assert(false);
    }

    return ip + 1;
}

std::pair<uint64_t, size_t> CPU::decode_address(ModBits mod, uint8_t rm, const Instruction& inst, const uint8_t* p_mod)
{
    if (rm == 0x4)
    {
        const SIB sib = reinterpret_cast<const SIB&>(p_mod[1]);
        uint64_t address = (reg64(sib.index, inst.rex_x) << sib.scale) + reg64(sib.base, inst.rex_b);
        switch (mod)
        {
        case MOD_INDIRECT_8BIT:
            return std::make_pair(address + *reinterpret_cast<const int8_t*>(p_mod + 2), 2u);
        case MOD_INDIRECT_32BIT:
            return std::make_pair(address + *reinterpret_cast<const int32_t*>(p_mod + 2), 5u);
        default:
            return std::make_pair(address, 1u);
        }
    }
    else if (rm == 5 && mod == 0)
    {
        // disp32
        // TODO: it is unclear if that values needs to be added to something, different assembler make different op-codes
        throw std::runtime_error("implementation uncertain");
        return std::make_pair(*reinterpret_cast<const int32_t*>(p_mod + 1), 4u);
    }
    else
    {
        uint64_t address = reg64(rm, inst.rex_b);
        switch (mod)
        {
        case MOD_INDIRECT_8BIT:
            return std::make_pair(address + *reinterpret_cast<const int8_t*>(p_mod + 1), 1u);
        case MOD_INDIRECT_32BIT:
            return std::make_pair(address + *reinterpret_cast<const int32_t*>(p_mod + 1), 4u);
        default:
            return std::make_pair(address, 0);
        }
    }
}

ptr_t CPU::execute_one(ptr_t ip)
{
    Instruction instruction = {0};
    const std::uint8_t* op = translate_instruction_address(ip);
    if (!op)
    {
        throw std::runtime_error("illegal instruction address");
    }
    while (true)
    {
        const auto& executor = s_opcodes[*op];
        if (!executor)
        {
            throw std::runtime_error("unsupported instruction");
        }
        auto next_ip = (this->*(executor.f))(instruction, ip);
        if (!executor.prefix)
        {
            return next_ip;
        }
        else
        {
            op += (next_ip - ip);
            ip = next_ip;
        }
    }
}

void CPU::execute_next()
{
    m_ip = execute_one(m_ip);
}

template<typename Op>
ptr_t CPU::op_al_imm8(Instruction& inst, ptr_t ip)
{
    flag_t flags = 0;
    if constexpr (Op::AFFECTED_FLAGS)
    {
        flags = m_flags;
    }
    auto& dst = reg8(REG_RAX, false, false);
    auto result = Op::call(dst, fetch_imm<uint8_t>(ip + 1), flags);
    if constexpr (Op::STORE_RESULT)
    {
        dst = result;
    }
    if constexpr (Op::AFFECTED_FLAGS)
    {
        m_flags = flags;
    }
    return ip + 2;
}

template<typename Op>
ptr_t CPU::op_eax_imm32(Instruction& inst, ptr_t ip)
{
    flag_t flags = 0;
    if constexpr (Op::AFFECTED_FLAGS)
    {
        flags = m_flags;
    }
    if (inst.operand_size_override)
    {
        auto& dst = reg16(REG_RAX);
        auto result = Op::call(dst, fetch_imm<uint16_t>(ip + 1), flags);
        if constexpr (Op::STORE_RESULT)
        {
            dst = result;
        }
        ip += 3;
    }
    else if (inst.rex_w)
    {
        auto& dst = reg64(REG_RAX, inst.rex_b);
        auto result = Op::call(dst, fetch_imm<uint64_t>(ip + 1), flags);
        if constexpr (Op::STORE_RESULT)
        {
            dst = result;
        }
        ip += 9;
    }
    else
    {
        auto& dst = reg32(REG_RAX);
        auto result = Op::call(dst, fetch_imm<uint32_t>(ip + 1), flags);
        if constexpr (Op::STORE_RESULT)
        {
            dst = result;
        }
        ip += 5;
    }
    if constexpr (Op::AFFECTED_FLAGS)
    {
        m_flags = flags;
    }
    return ip;
}

ptr_t CPU::execute_Jcc_7x(Instruction& instruction, ptr_t ip)
{
    auto next = ip + 2;
    auto p = get_instruction_address(ip);
    auto imm8 = reinterpret_cast<const std::int8_t*>(p + 1);
    switch(p[0])
    {
    case 0x72: //JB rel8 / JC rel8
        if ((m_flags & FLAG_CF) == FLAG_CF)
        {
            next += *imm8;
        }
        break;

    case 0x73: //JAE rel8
        if ((m_flags & FLAG_CF) == 0)
        {
            next += *imm8;
        }
        break;

    case 0x74: //JE rel8
        if ((m_flags & FLAG_ZF) == FLAG_ZF)
        {
            next += *imm8;
        }
        break;

    case 0x75: //JNE rel8
        if ((m_flags & FLAG_ZF) == 0)
        {
            next += *imm8;
        }
        break;

    case 0x76: //JBE rel8
        if ((m_flags & (FLAG_CF | FLAG_ZF)) != 0)
        {
            next += *imm8;
        }
        break;

    case 0x77: //JA rel8
        if ((m_flags & (FLAG_CF | FLAG_ZF)) == 0)
        {
            next += *imm8;
        }
        break;

    case 0x78: //JS rel8
        if ((m_flags & FLAG_SF) == FLAG_SF)
        {
            next += *imm8;
        }
        break;

    case 0x79: //JNS rel8
        if ((m_flags & FLAG_SF) == 0)
        {
            next += *imm8;
        }
        break;

    default:
        throw std::runtime_error("unsupported instruction");
    }

    return next;
}

template<typename Op> ptr_t CPU::op_rm8_r8(Instruction& inst, ptr_t ip)
{
    auto p = get_instruction_address(ip);
    flag_t flags = 0;
    if constexpr (Op::AFFECTED_FLAGS)
    {
        flags = m_flags;
    }
    const ModRM modrm = reinterpret_cast<const ModRM&>(p[1]);
    if (modrm.mod == MOD_DIRECT_REGISTER)
    {
        auto& dst = reg8(modrm.rm, inst.rex_present, inst.rex_b);
        auto result = Op::call(dst, reg8(modrm.reg, inst.rex_present, inst.rex_r), flags);
        if constexpr (Op::STORE_RESULT)
        {
            dst = result;
        }
        ip += 2;
    }
    else
    {
        auto dst_address = decode_address(modrm.mod, modrm.rm, inst, p + 1);
        uint8_t dst = load<uint8_t>(dst_address.first);
        dst = Op::call(dst, reg8(modrm.reg, inst.rex_present, inst.rex_r), flags);
        if constexpr (Op::STORE_RESULT)
        {
            store(dst_address.first, dst);
        }
        ip += 2 + dst_address.second;
    }
    if constexpr (Op::AFFECTED_FLAGS)
    {
        m_flags = flags;
    }
    return ip;
}

ptr_t CPU::execute_MOV_89(Instruction& inst, ptr_t ip)
{
    auto p = get_instruction_address(ip);
    const ModRM modrm = reinterpret_cast<const ModRM&>(p[1]);
    if (modrm.mod == MOD_DIRECT_REGISTER)
    {
        if (inst.operand_size_override)
        {
            reg16(modrm.rm) = reg16(modrm.reg);
        }
        else if (inst.rex_w)
        {
            reg64(modrm.rm, inst.rex_b) = reg64(modrm.reg, inst.rex_r);
        }
        else
        {
            reg32(modrm.rm) = reg32(modrm.reg);
        }
        return ip + 2;
    }
    else
    {
        auto dst = decode_address(modrm.mod, modrm.rm, inst, p + 1);
        if (inst.operand_size_override)
        {
            store(dst.first, reg16(modrm.reg));
        }
        else if (inst.rex_w)
        {
            store(dst.first, reg64(modrm.reg, inst.rex_r));
        }
        else
        {
            store(dst.first, reg32(modrm.reg));
        }
        return ip + 2 + dst.second;
    }
}

ptr_t CPU::execute_MOV_8A(Instruction& inst, ptr_t ip)
{
    auto p = get_instruction_address(ip);
    const ModRM modrm = reinterpret_cast<const ModRM&>(p[1]);
    if (modrm.mod == MOD_DIRECT_REGISTER)
    {
        reg8(modrm.rm, inst.rex_present, inst.rex_b) = reg8(modrm.reg, inst.rex_present, inst.rex_r);
        return ip + 2;
    }
    else
    {
        auto src = decode_address(modrm.mod, modrm.rm, inst, p + 1);
        reg8(modrm.reg, inst.rex_present, inst.rex_r) = load<uint8_t>(src.first);
        return ip + 2 + src.second;
    }
}

ptr_t CPU::execute_MOV_8B(Instruction& inst, ptr_t ip)
{
    auto p = get_instruction_address(ip);
    const ModRM modrm = reinterpret_cast<const ModRM&>(p[1]);
    if (modrm.mod == MOD_DIRECT_REGISTER)
    {
        if (inst.operand_size_override)
        {
            reg16(modrm.reg) = reg16(modrm.rm);
        }
        else if (inst.rex_w)
        {
            reg64(modrm.reg, inst.rex_r) = reg64(modrm.rm, inst.rex_b);
        }
        else
        {
            reg32(modrm.reg) = reg32(modrm.rm);
        }
        return ip + 2;
    }
    else
    {
        auto src = decode_address(modrm.mod, modrm.rm, inst, p + 1);
        if (inst.operand_size_override)
        {
            reg16(modrm.reg) = load<uint16_t>(src.first);
        }
        else if (inst.rex_w)
        {
            reg64(modrm.reg, inst.rex_r) = load<uint64_t>(src.first);
        }
        else
        {
            reg32(modrm.reg) = load<uint32_t>(src.first);
        }
        return ip + 2 + src.second;
    }
}

ptr_t CPU::execute_MOV_B0(Instruction& inst, ptr_t ip)
{
    auto p = get_instruction_address(ip);
    reg8(p[0] & 0x07, inst.rex_present, inst.rex_b) = p[1];
    return ip + 2;
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

ptr_t CPU::execute_JMP(Instruction& instruction, ptr_t ip)
{
    auto p = get_instruction_address(ip);
    switch(p[0])
    {
    case 0xe9: //JMP rel32
        return ip + 5 + *reinterpret_cast<const std::int32_t*>(p + 1);
    case 0xeb: //JMP rel8
        return ip + 2 + *reinterpret_cast<const std::int8_t*>(p + 1);
    default:
        throw std::runtime_error("unsupported instruction");
    }
}

ptr_t CPU::execute_HLT_F4(Instruction& i, ptr_t ip) { return ip; } // TODO: maybe throw a HLT exception, but required privilege level 0
ptr_t CPU::execute_CMC_F5(Instruction& i, ptr_t ip) { m_flags ^=  FLAG_CF; return ip + 1; }
ptr_t CPU::execute_CLC_F8(Instruction& i, ptr_t ip) { m_flags &= ~FLAG_CF; return ip + 1; }
ptr_t CPU::execute_STC_F9(Instruction& i, ptr_t ip) { m_flags |=  FLAG_CF; return ip + 1; }
ptr_t CPU::execute_CLI_FA(Instruction& i, ptr_t ip) { m_flags &= ~FLAG_IF; return ip + 1; }
ptr_t CPU::execute_STI_FB(Instruction& i, ptr_t ip) { m_flags |=  FLAG_IF; return ip + 1; }
ptr_t CPU::execute_CLD_FC(Instruction& i, ptr_t ip) { m_flags &= ~FLAG_DF; return ip + 1; }
ptr_t CPU::execute_STD_FD(Instruction& i, ptr_t ip) { m_flags |=  FLAG_DF; return ip + 1; }

ptr_t CPU::execute_0F(Instruction&, ptr_t ip)
{
    auto p = get_instruction_address(ip);
    auto op_code = p[1];
    switch (op_code)
    {
    case 0x05: // SYSCALL
        dispatch_syscall(ip + 2);
        return ip + 2;
    }
    throw std::runtime_error("Not implemented");
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
