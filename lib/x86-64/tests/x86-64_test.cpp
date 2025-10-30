#include <boost/test/unit_test.hpp>

#include "x86-64.h"
#include "memory_adapter.h"

using namespace cpu::X86_64;

BOOST_AUTO_TEST_SUITE(Amd64_suite)

BOOST_AUTO_TEST_CASE(default_test)
{
    const void* inst = nullptr;
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(&mem);
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0);
}

BOOST_AUTO_TEST_CASE(mov_reg_imm32_test)
{
    const std::uint8_t inst[] = {
        0xb8, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x12345678
        0xbc, 0x78, 0x56, 0x34, 0x00, // mov esp, 0x00345678
    };
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(&mem);
    BOOST_REQUIRE_EQUAL(cpu.execute_one(0), 5);
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0x12345678);

    BOOST_REQUIRE_EQUAL(cpu.execute_one(5), 10);
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RSP), 0x00345678);
}

BOOST_AUTO_TEST_CASE(mov_reg_imm16_test)
{
    // mov ax, 0x4321
    const std::uint8_t inst[] = {0x66, 0xb8, 0x21, 0x43};
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(&mem);
    // mov eax, 0x12345678
    cpu.setRegister(REG_RAX, 0x12345678);
    BOOST_REQUIRE_EQUAL(cpu.execute_one(0), 4);
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0x12344321);
}

BOOST_AUTO_TEST_CASE(mov_reg_imm64_test)
{
    // mov rcx, 0x100000000
    std::uint8_t inst[] = {0x48, 0xb9, 0, 0, 0, 0, 1, 0, 0, 0};
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(&mem);
    BOOST_REQUIRE_EQUAL(cpu.execute_one(0), 10);
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RCX), 0x100000000);
    // mov rsp, 0x400000000
    inst[0] = 0x48; inst[1] = 0xbc; inst[6] = 4;
    BOOST_REQUIRE_EQUAL(cpu.execute_one(0), 10);
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RSP), 0x400000000);
    // mov r8, 0x200000000
    inst[0] = 0x49; inst[1] = 0xb8; inst[6] = 2;
    BOOST_REQUIRE_EQUAL(cpu.execute_one(0), 10);
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_R8), 0x200000000);
}

BOOST_AUTO_TEST_CASE(mov_reg_imm8_test)
{
    // mov cl, 0x05
    // mov ch, 0x08
    const std::uint8_t inst[] = {0xb1, 0x05, 0xb5, 0x08};
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(&mem);

    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RCX), 0);
    BOOST_REQUIRE_EQUAL(cpu.execute_one(0), 2);
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RCX), 0x0005);
    BOOST_REQUIRE_EQUAL(cpu.execute_one(2), 4);
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RCX), 0x0805);
}

BOOST_AUTO_TEST_CASE(mov_reg_imm8_with_rex_test)
{
    const std::uint8_t inst[] = {
        0x40, 0xb0, 0,
        0x40, 0xb1, 1,
        0x40, 0xb2, 2,
        0x40, 0xb3, 3,
        0x40, 0xb4, 4,
        0x40, 0xb5, 5,
        0x40, 0xb6, 6,
        0x40, 0xb7, 7,
        0x41, 0xb0, 8, 
        0x41, 0xb1, 9, 
        0x41, 0xb2, 10, 
        0x41, 0xb3, 11, 
        0x41, 0xb4, 12, 
        0x41, 0xb5, 13, 
        0x41, 0xb6, 14, 
        0x41, 0xb7, 15, 
    };
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(&mem);

    for (int n = 0; n < 16; ++n)
    {
        BOOST_REQUIRE_NO_THROW(cpu.execute_next());
        BOOST_CHECK_EQUAL(cpu.getRegister(static_cast<Register>(n)), n);
    }
}

BOOST_AUTO_TEST_CASE(mov_reg8_reg8_test)
{
    const std::uint8_t inst[] = {
        0x88, 0xc1, // mov cl, al
        0x88, 0xe7, // mov bh, ah
        0x88, 0xc4, // mov ah, al
    };
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(&mem);
    cpu.setRegister(REG_RAX, 0x0201);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // mov cl, al
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0x0201);
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RBX), 0x0000);
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RCX), 0x0001);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // mov bh, ah
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0x0201);
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RBX), 0x0200);
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RCX), 0x01);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // mov ah, al
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0x0101);
}

BOOST_AUTO_TEST_CASE(mov_reg32_reg32_test)
{
    const std::uint8_t inst[] = {
        0x89, 0xc3, // mov ebx, eax
        0x89, 0xdc, // mov esp, ebx
        0x66, 0x89, 0xc1, // mov cx, ax
        0x48, 0x89, 0xcd, // mov rbp, rcx
        0x49, 0x89, 0xc5, // mov r13, rax
        0x4d, 0x89, 0xee, // mov r14, r13
    };
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(&mem);
    cpu.setRegister(REG_RAX, 0xFFFF0201);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // mov ebx, eax
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0xFFFF0201);
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RBX), 0xFFFF0201);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // mov esp, ebx
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RBX), 0xFFFF0201);
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RSP), 0xFFFF0201);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // mov cx, ax
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RCX), 0x00000201);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // mov rbp, rcx
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RBP), 0x00000201);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // mov r13, rax
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_R13), 0xFFFF0201);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // mov r14, r13
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_R14), 0xFFFF0201);
}

BOOST_AUTO_TEST_CASE(mov_mem_reg_test)
{
    std::uint8_t inst[] = {
        0, 0, 0, 0,
        0x89, 0x01, // mov [rcx], eax
        0x66, 0x89, 0x01, // mov [rcx], ax
        0x88, 0x01, // mov [rcx], al
        0x88, 0x21, // mov [rcx], ah
        0x89, 0x41, 0x02, // mov [rcx+2], eax
        0x88, 0x61, 0x03, // mov [rcx+3], ah
    };
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(&mem);
    cpu.setIP(4);
    cpu.setRegister(REG_RAX, 0xDEADBEAF);
    cpu.setRegister(REG_RCX, 0);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // mov [rcx], eax
    BOOST_CHECK_EQUAL(*reinterpret_cast<uint32_t*>(inst), 0xDEADBEAF);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // mov [rcx], ax
    BOOST_CHECK_EQUAL(*reinterpret_cast<uint16_t*>(inst), 0xBEAF);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // mov [rcx], al
    BOOST_CHECK_EQUAL(*inst, 0xAF);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // mov [rcx], ah
    BOOST_CHECK_EQUAL(*inst, 0xBE);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // mov [rcx+2], eax
    BOOST_CHECK_EQUAL(*reinterpret_cast<uint32_t*>(inst + 2), 0xDEADBEAF);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // mov [rcx+3], ah
    BOOST_CHECK_EQUAL(inst[3], 0xBE);
}

BOOST_AUTO_TEST_CASE(mov_memsib_reg_test)
{
    std::uint8_t inst[] = {
        0, 0, 0, 0,
        0x66, 0x89, 0x14, 0x08, // mov [rax+rcx], dx
        0x88, 0x54, 0x08, 0x01, // mov [rax+rcx+1], dl
        0x88, 0x14, 0x48, // mov [rax+rcx*2], dl
    };
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(&mem);
    cpu.setRegister(REG_RDX, 0xDEADBEAF);
    cpu.setRegister(REG_RAX, 1);
    cpu.setRegister(REG_RCX, 1);

    cpu.setIP(4);
    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // mov [rax+rcx], dx
    BOOST_CHECK_EQUAL(*reinterpret_cast<uint32_t*>(inst), 0xBEAF0000);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // mov [rax+rcx+1], dh
    BOOST_CHECK_EQUAL(*reinterpret_cast<uint32_t*>(inst), 0xAFAF0000);

    *reinterpret_cast<uint32_t*>(inst) = 0;
    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // mov [rax+rcx*2], dl
    BOOST_CHECK_EQUAL(*reinterpret_cast<uint32_t*>(inst), 0xAF000000);
}

#if 0
BOOST_AUTO_TEST_CASE(mov_memdirect_reg_test)
{
    std::uint8_t inst[] = {
        0, 0, 0, 0,
        0x88, 0x15, 0x02, 0, 0, 0, // mov [2], dl
        0x88, 0x35, 0x03, 0, 0, 0, // mov [3], dh
    };
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(mem);
    cpu.setRegister(REG_RDX, 0xDEADBEAF);

    cpu.setIP(4);
    *reinterpret_cast<uint32_t*>(inst) = 0;
    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // mov [2], dl
    BOOST_CHECK_EQUAL(*reinterpret_cast<uint32_t*>(inst), 0x00AF0000);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // mov [3], dh
    BOOST_CHECK_EQUAL(*reinterpret_cast<uint32_t*>(inst), 0xBEAF0000);
}
#endif

BOOST_AUTO_TEST_CASE(mov_reg_mem_test)
{
    std::uint8_t inst[] = {
        0x8a, 0x01, // mov al, [ecx]
        0x8a, 0x61, 0x01, // mov ah, [ecx+1]
        0x66, 0x8b, 0x51, 0x02, // mov dx, [rcx+2]
    };
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(&mem);
    cpu.setRegister(REG_RCX, 0);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // mov al, [ecx]
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0x8a);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // mov ah, [ecx+1]
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0x018a);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // mov dx, [rcx+2]
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RDX), 0x618a);
}

BOOST_AUTO_TEST_CASE(jmp_rel_test)
{
    // jmp 0
    // jmp -4
    const std::uint8_t inst[] = {
        0xeb, 0x00,
        0xeb, static_cast<std::uint8_t>(-4),
        0xe9, 0x01, 0x02, 0, 0, // JMP 0x00000201
    };
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(&mem);
    BOOST_REQUIRE_EQUAL(cpu.execute_one(0), 2);
    BOOST_REQUIRE_EQUAL(cpu.execute_one(2), 0);
    BOOST_REQUIRE_EQUAL(cpu.execute_one(4), 4+5+0x201);
}

BOOST_AUTO_TEST_CASE(add_sub_al_imm_test)
{
    const std::uint8_t inst[] = {
        0x04, 0x01, // add al, 1
        0x04, 0x07, // add al, 7
        0x04, static_cast<std::uint8_t>(-8), // add al, -8
        0x04, static_cast<std::uint8_t>(-8), // add al, -8
        0x2c, static_cast<std::uint8_t>(-8), // sub al, -8
    };
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(&mem);
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, 0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_SF, 0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_PF, 0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_CF, 0);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next());
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 1);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, 0);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next());
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 8);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, 0);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next());
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, FLAG_ZF);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_SF, 0);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // add al, -8
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0xf8);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, 0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_SF, FLAG_SF);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // sub al, -8
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0x00);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, FLAG_ZF);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_SF, 0);
}

BOOST_AUTO_TEST_CASE(add_rax_imm_test)
{
    const std::uint8_t inst[] = {
        0x04, 0xff, // add al, -1
        0x66, 0x05, 0xff, 0xff, // add ax, -1
        0x05, 0xff, 0xff, 0xff, 0xff, // add eax, -1
        0x48, 0x05, 0xff, 0xff, 0xff, 0xff, // add rax, -1
    };
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(&mem);

    cpu.setRegister(REG_RAX, 0);
    BOOST_REQUIRE_NO_THROW(cpu.execute_next());
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), static_cast<uint8_t>(-1));

    cpu.setRegister(REG_RAX, 0);
    BOOST_REQUIRE_NO_THROW(cpu.execute_next());
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), static_cast<uint16_t>(-1));

    cpu.setRegister(REG_RAX, 0);
    BOOST_REQUIRE_NO_THROW(cpu.execute_next());
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), static_cast<uint32_t>(-1));

    cpu.setRegister(REG_RAX, 0);
    BOOST_REQUIRE_NO_THROW(cpu.execute_next());
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), static_cast<uint64_t>(-1));
}

BOOST_AUTO_TEST_CASE(adc_al_imm_test)
{
    const std::uint8_t inst[] = {
        0x14, 0x01, // add al, 1
        0xf9, // stc
        0x14, 0x07, // add al, 7
        0x14, static_cast<std::uint8_t>(-8), // add al, -8
        0x14, static_cast<std::uint8_t>(-8), // add al, -8
    };
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(&mem);
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, 0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_SF, 0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_PF, 0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_CF, 0);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next());
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 1);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, 0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_CF, 0);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next());
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_CF, 1);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next());
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 9);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, 0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_CF, 0);
}

BOOST_AUTO_TEST_CASE(add_eax_imm_test)
{
    const std::uint8_t inst[] = {
        0x05, 0xFF, 0xFF, 0xFF, 0xFF, // add eax, 0xFFFFFFFF
        0x05, 0x02, 0, 0, 0,  // add eax, 2
    };
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(&mem);
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, 0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_SF, 0);

    BOOST_REQUIRE_EQUAL(cpu.execute_one(0), 5);
    BOOST_CHECK_EQUAL(static_cast<int32_t>(cpu.getRegister(REG_RAX)), -1);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, 0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_SF, FLAG_SF);

    BOOST_REQUIRE_EQUAL(cpu.execute_one(5), 10);
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 1);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, 0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_SF, 0);
}

BOOST_AUTO_TEST_CASE(add_op_test)
{
    std::uint8_t inst[] = {
        0x00, 0xd8, // add al, bl
        0x00, 0xc4, // add ah, bl
        0x00, 0x41, 1, // add [rcx + 1], al
        0x66, 0x03, 0x12, // add dx, [rdx]
    };
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(&mem);
    cpu.setRegister(REG_RBX, 0x05);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next());
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0x0005);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, 0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_SF, 0);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next());
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0x0505);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, 0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_SF, 0);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // add [rcx + 1], al
    BOOST_CHECK_EQUAL(inst[1], 0xd8 + 0x05);

    cpu.setRegister(REG_RDX, 0);
    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // add dx, [rdx]
    BOOST_CHECK_EQUAL(*reinterpret_cast<uint16_t*>(inst), 0xdd00);
}

BOOST_AUTO_TEST_CASE(add_jnz_imm_test)
{
    const std::uint8_t inst[] = {
        0x04, 0xFF, // add al, 0xFF
        0x75, static_cast<std::uint8_t>(-4),  // JNZ -4
    };
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(&mem);
    cpu.setRegister(REG_RAX, 2);
    BOOST_REQUIRE_EQUAL(cpu.execute_one(0), 2);
    BOOST_REQUIRE_EQUAL(cpu.execute_one(2), 0);
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 1);

    BOOST_REQUIRE_EQUAL(cpu.execute_one(0), 2);
    BOOST_REQUIRE_EQUAL(cpu.execute_one(2), 4);
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0);
}

BOOST_AUTO_TEST_CASE(op_rm8_imm8_test)
{
    std::uint8_t inst[] = {
        0x80, 0xc3, 1, // add bl, 1
        0xf9, // stc
        0x80, 0xd3, 2, // adc bl, 2
        0x80, 0xca, 0x33, // or dl, 0x33

        0x80, 0x41, 0x02, 0xff, // add byte [rcx+2], -1
        0x80, 0x61, 0x01, 0xf0, // and byte [rcx+1], 0xf0
    };
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(&mem);
    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // add bl, 0x1
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RBX), 1);
    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // stc
    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // adc bl, 2
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RBX), 4);
    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // or dl, 0x33
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RDX), 0x33);

    BOOST_CHECK_EQUAL(inst[2], 1);
    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // add byte [rcx+2], -1
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RCX), 0);
    BOOST_CHECK_EQUAL(inst[2], 0);

    BOOST_CHECK_EQUAL(inst[1], 0xc3);
    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // and byte [rcx+1], 0xf0
    BOOST_CHECK_EQUAL(inst[1], 0xc0);
}

BOOST_AUTO_TEST_CASE(logical_al_imm8_test)
{
    const std::uint8_t inst[] = {
        0x34, 0x00, // xor al, 0
        0x34, 0xFF, // xor al, 0xFF
        0x24, 0xF0, // and al, 0xF0
        0x0C, 0x02, // or al, 0x02
    };
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(&mem);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next());
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0x00);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, FLAG_ZF);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_SF, 0);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next());
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0xFF);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, 0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_SF, FLAG_SF);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // and al, 0xF0
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0xF0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, 0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_SF, FLAG_SF);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // or al, 0x02
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0xF2);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, 0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_SF, FLAG_SF);
}

BOOST_AUTO_TEST_CASE(test_test)
{
    const std::uint8_t inst[] = {
        0xa8, 0x00, // test al, 0
        0xa8, 0x0F, // test al, 0x0f
        0xa8, 0x80, // test al, 0x80
    };
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(&mem);
    cpu.setRegister(REG_RAX, 0xF0);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // test al, 0
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0xF0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, FLAG_ZF);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // test al, 0x0f
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0xF0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, FLAG_ZF);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // test al, 0x80
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0xF0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, 0);
}

BOOST_AUTO_TEST_CASE(xor_eax_imm32_test)
{
    const std::uint8_t inst[] = {
        0x35, 0, 0, 0, 0, // xor eax, 0
        0x66, 0x35, 0xFF, 0x0F, // xor ax, 0x0FFF
        0x35, 0, 0, 0, 0x80, // xor eax, 0x80000000
    };
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(&mem);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next());
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, FLAG_ZF);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_SF, 0);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next());
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0x0FFF);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, 0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_SF, 0);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next());
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 0x80000FFF);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, 0);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_SF, FLAG_SF);
}

BOOST_AUTO_TEST_CASE(cmp_test)
{
    const std::uint8_t inst[] = {
        0x39, 0xC0, // cmp eax, eax
        0x39, 0xD8, // cmp eax, edx
        0x3D, 0xA0, 0, 0, 0, // cmp eax, 0xA0
    };
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(&mem);

    cpu.setRegister(REG_RAX, 0xA0);
    cpu.setRegister(REG_RDX, 4);
    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // CMP EAX, EAX
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, FLAG_ZF);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // CMP EAX, EDX
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, 0);

    BOOST_REQUIRE_NO_THROW(cpu.execute_next()); // cmp eax, 0xA0
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_ZF, FLAG_ZF);
}

BOOST_AUTO_TEST_CASE(flag_modifiers_tests)
{
    const std::uint8_t inst[] = {
        0xf9, // STC
        0xf8, // CLC
        0xf5, // CMC
        0xfd, // STD
        0xfc, // CLD
        0xfb, // STI
        0xfa, // CLI
    };
    kernel::MemoryAdapter mem(inst, 0);
    CPU cpu(&mem);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_CF, 0);
    BOOST_REQUIRE_EQUAL(cpu.execute_one(0), 1);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_CF, FLAG_CF);
    BOOST_REQUIRE_EQUAL(cpu.execute_one(1), 2);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_CF, 0);
    BOOST_REQUIRE_EQUAL(cpu.execute_one(2), 3);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_CF, FLAG_CF);
    BOOST_REQUIRE_EQUAL(cpu.execute_one(2), 3);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_CF, 0);

    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_DF, 0);
    BOOST_REQUIRE_EQUAL(cpu.execute_one(3), 4);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_DF, FLAG_DF);
    BOOST_REQUIRE_EQUAL(cpu.execute_one(4), 5);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_DF, 0);

    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_IF, 0);
    BOOST_REQUIRE_EQUAL(cpu.execute_one(5), 6);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_IF, FLAG_IF);
    BOOST_REQUIRE_EQUAL(cpu.execute_one(6), 7);
    BOOST_CHECK_EQUAL(cpu.getFlags() & FLAG_IF, 0);
}

BOOST_AUTO_TEST_CASE(syscall_tests)
{
    class TestKernel : public kernel::MemoryAdapter
    {
    public:
        TestKernel(const void* phy_address, std::uintptr_t virt_address)
        : MemoryAdapter(phy_address, virt_address)
        {}

        kernel::KernelType getType() const
        {
            return kernel::KernelType::Linux64;
        }

        uint64_t syscall(uint64_t number, const uint64_t* args, size_t num_args) override
        {
            if (number == 60)
            {
                ret_code = args[0];
            }
            return 123;
        }
        uint64_t ret_code = 0;
    };

    const std::uint8_t inst[] = {
        0xb8, 60, 0, 0, 0, // mov eax, 60
        0xbf, 1, 0, 0, 0, // mov edi, 1 (return code)
        0x0f, 0x05, // SYSCALL
    };
    TestKernel kernel(inst, 0);
    CPU cpu(&kernel);
    BOOST_REQUIRE_NO_THROW(cpu.execute_next());
    BOOST_REQUIRE_NO_THROW(cpu.execute_next());

    BOOST_CHECK_EQUAL(kernel.ret_code, 0);
    BOOST_REQUIRE_NO_THROW(cpu.execute_next());
    BOOST_CHECK_EQUAL(cpu.getRegister(REG_RAX), 123);
    BOOST_CHECK_EQUAL(kernel.ret_code, 1);
    BOOST_CHECK_EQUAL(cpu.getIP(), 12);
}

BOOST_AUTO_TEST_SUITE_END()
