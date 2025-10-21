#pragma once

#include "x86-64_types.h"
#include "x86-64_utils.h"
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
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            bool cf = utils::add_with_carry(false, dst, imm);
            update_flags(flags, dst, cf);
            return dst;
        }
    };

    struct OpAdc
    {
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            bool cf = utils::add_with_carry((flags & FLAG_CF) == FLAG_CF, dst, imm);
            update_flags(flags, dst, cf);
            return dst;
        }
    };

    struct OpAnd
    {
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            dst &= imm;
            update_flags(flags, dst);
            return dst;
        }
    };

    struct OpOr
    {
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
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            bool cf = utils::sub_with_borrow(false, dst, imm);
            update_flags(flags, dst, cf);
            return dst;
        }
    };

    struct OpSbb
    {
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            bool cf = utils::sub_with_borrow((flags & FLAG_CF) == FLAG_CF, dst, imm);
            update_flags(flags, dst, cf);
            return dst;
        }
    };

    struct OpXor
    {
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            dst ^= imm;
            update_flags(flags, dst);
            return dst;
        }
    };
}
