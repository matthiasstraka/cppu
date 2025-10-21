#pragma once

#include "x86-64_types.h"
#include "carry_addsub.h"
#include <cstdint>
#include <utility>

namespace cpu::X86_64
{
    template<typename T>
    inline void update_flags(flag_t& flags, T value, bool cf = false)
    {
        constexpr T SIGNBIT = static_cast<T>(1) << (sizeof(T) * 8 - 1);
        flags &= ~(FLAG_ZF | FLAG_SF | FLAG_CF); // clear all flags, set conditionally
        flags |= static_cast<flag_t>(value == 0) << FLAGSHIFT_ZF;
        flags |= static_cast<flag_t>((value & SIGNBIT) == SIGNBIT) << FLAGSHIFT_SF;
        flags |= static_cast<flag_t>(cf) << FLAGSHIFT_CF;
        // TODO: OF, AF, PF
    }

    struct OpAdd
    {
        static constexpr flag_t AFFECTED_FLAGS = FLAG_ZF | FLAG_SF | FLAG_CF;
        static constexpr bool STORE_RESULT = true;
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            bool cf = cpu_utils::add_with_carry(false, dst, imm);
            update_flags(flags, dst, cf);
            return dst;
        }
    };

    struct OpAdc
    {
        static constexpr flag_t AFFECTED_FLAGS = FLAG_ZF | FLAG_SF | FLAG_CF;
        static constexpr bool STORE_RESULT = true;
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            bool cf = cpu_utils::add_with_carry((flags & FLAG_CF) == FLAG_CF, dst, imm);
            update_flags(flags, dst, cf);
            return dst;
        }
    };

    struct OpAnd
    {
        static constexpr flag_t AFFECTED_FLAGS = FLAG_ZF | FLAG_SF | FLAG_CF;
        static constexpr bool STORE_RESULT = true;
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            dst &= imm;
            update_flags(flags, dst);
            return dst;
        }
    };

    struct OpMov
    {
        static constexpr flag_t AFFECTED_FLAGS = 0;
        static constexpr bool STORE_RESULT = true;
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            return imm;
        }
    };

    struct OpOr
    {
        static constexpr flag_t AFFECTED_FLAGS = FLAG_ZF | FLAG_SF | FLAG_CF;
        static constexpr bool STORE_RESULT = true;
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            dst |= imm;
            update_flags(flags, dst);
            return dst;
        }
    };

    struct OpSub
    {
        static constexpr flag_t AFFECTED_FLAGS = FLAG_ZF | FLAG_SF | FLAG_CF;
        static constexpr bool STORE_RESULT = true;
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            bool cf = cpu_utils::sub_with_borrow(false, dst, imm);
            update_flags(flags, dst, cf);
            return dst;
        }
    };

    struct OpSbb
    {
        static constexpr flag_t AFFECTED_FLAGS = FLAG_ZF | FLAG_SF | FLAG_CF;
        static constexpr bool STORE_RESULT = true;
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            bool cf = cpu_utils::sub_with_borrow((flags & FLAG_CF) == FLAG_CF, dst, imm);
            update_flags(flags, dst, cf);
            return dst;
        }
    };

    struct OpTest
    {
        static constexpr flag_t AFFECTED_FLAGS = FLAG_ZF | FLAG_SF | FLAG_CF;
        static constexpr bool STORE_RESULT = false;
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            update_flags(flags, dst & imm);
            return dst;
        }
    };

    struct OpXor
    {
        static constexpr flag_t AFFECTED_FLAGS = FLAG_ZF | FLAG_SF | FLAG_CF;
        static constexpr bool STORE_RESULT = true;
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            dst ^= imm;
            update_flags(flags, dst);
            return dst;
        }
    };
}
