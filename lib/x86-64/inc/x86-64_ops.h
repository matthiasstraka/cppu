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

    struct Op
    {
        static constexpr flag_t AFFECTED_FLAGS = 0;
        static constexpr bool LOAD_FIRST = true;
        static constexpr bool STORE_RESULT = true;
    };

    struct OpNop : Op
    {
        static constexpr flag_t AFFECTED_FLAGS = 0;
        static constexpr bool LOAD_FIRST = false;
        static constexpr bool STORE_RESULT = false;
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            // NOP
            return 0;
        }
    };

    struct OpAdd : Op
    {
        static constexpr flag_t AFFECTED_FLAGS = FLAG_ZF | FLAG_SF | FLAG_CF;
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            bool cf = cpu_utils::add_with_carry(false, dst, imm);
            update_flags(flags, dst, cf);
            return dst;
        }
    };

    struct OpAdc : Op
    {
        static constexpr flag_t AFFECTED_FLAGS = FLAG_ZF | FLAG_SF | FLAG_CF;
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            bool cf = cpu_utils::add_with_carry((flags & FLAG_CF) == FLAG_CF, dst, imm);
            update_flags(flags, dst, cf);
            return dst;
        }
    };

    struct OpAnd : Op
    {
        static constexpr flag_t AFFECTED_FLAGS = FLAG_ZF | FLAG_SF | FLAG_CF;
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            dst &= imm;
            update_flags(flags, dst);
            return dst;
        }
    };

    struct OpCmp : Op
    {
        static constexpr flag_t AFFECTED_FLAGS = FLAG_ZF | FLAG_SF | FLAG_CF;
        static constexpr bool STORE_RESULT = false;
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            update_flags(flags, dst - imm);
            return 0;
        }
    };

    struct OpMov : Op
    {
        static constexpr bool LOAD_FIRST = false;
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            return imm;
        }
    };

    struct OpOr : Op
    {
        static constexpr flag_t AFFECTED_FLAGS = FLAG_ZF | FLAG_SF | FLAG_CF;
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            dst |= imm;
            update_flags(flags, dst);
            return dst;
        }
    };

    struct OpSub : Op
    {
        static constexpr flag_t AFFECTED_FLAGS = FLAG_ZF | FLAG_SF | FLAG_CF;
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            bool cf = cpu_utils::sub_with_borrow(false, dst, imm);
            update_flags(flags, dst, cf);
            return dst;
        }
    };

    struct OpSbb : Op
    {
        static constexpr flag_t AFFECTED_FLAGS = FLAG_ZF | FLAG_SF | FLAG_CF;
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            bool cf = cpu_utils::sub_with_borrow((flags & FLAG_CF) == FLAG_CF, dst, imm);
            update_flags(flags, dst, cf);
            return dst;
        }
    };

    struct OpTest : Op
    {
        static constexpr flag_t AFFECTED_FLAGS = FLAG_ZF | FLAG_SF | FLAG_CF;
        static constexpr bool STORE_RESULT = false;
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            update_flags(flags, dst & imm);
            return 0;
        }
    };

    struct OpXor : Op
    {
        static constexpr flag_t AFFECTED_FLAGS = FLAG_ZF | FLAG_SF | FLAG_CF;
        template<typename T>
        static inline T call(T dst, T imm, flag_t& flags)
        {
            dst ^= imm;
            update_flags(flags, dst);
            return dst;
        }
    };

    struct Condition
    {
    };

    struct CondA : Condition
    {
        static inline bool test(flag_t flags) { return (flags & (FLAG_CF | FLAG_ZF)) == 0; }
    };
    struct CondNC : Condition
    {
        static inline bool test(flag_t flags) { return (flags & FLAG_CF) == 0; }
    };
    struct CondC : Condition
    {
        static inline bool test(flag_t flags) { return (flags & FLAG_CF) == FLAG_CF; }
    };
    struct CondBE : Condition
    {
        static inline bool test(flag_t flags) { return (flags & (FLAG_CF | FLAG_ZF)) != 0; }
    };
    struct CondO : Condition
    {
        static inline bool test(flag_t flags) { return (flags & FLAG_OF) == FLAG_CF; }
    };
    struct CondNO : Condition
    {
        static inline bool test(flag_t flags) { return (flags & FLAG_OF) == 0; }
    };
    struct CondZ : Condition
    {
        static inline bool test(flag_t flags) { return (flags & FLAG_ZF) == FLAG_ZF; }
    };
    struct CondNZ : Condition
    {
        static inline bool test(flag_t flags) { return (flags & FLAG_ZF) == 0; }
    };
    struct CondS : Condition
    {
        static inline bool test(flag_t flags) { return (flags & FLAG_SF) == FLAG_SF; }
    };
    struct CondNS : Condition
    {
        static inline bool test(flag_t flags) { return (flags & FLAG_SF) == 0; }
    };
    struct CondP : Condition
    {
        static inline bool test(flag_t flags) { return (flags & FLAG_PF) == FLAG_PF; }
    };
    struct CondNP : Condition
    {
        static inline bool test(flag_t flags) { return (flags & FLAG_PF) == 0; }
    };
    struct CondL : Condition
    {
        static inline bool test(flag_t flags) { return ((flags & FLAG_SF) == FLAG_SF) != ((flags & FLAG_OF) == FLAG_OF); }
    };
    struct CondGE : Condition
    {
        static inline bool test(flag_t flags) { return ((flags & FLAG_SF) == FLAG_SF) == ((flags & FLAG_OF) == FLAG_OF); }
    };
    struct CondLE : Condition
    {
        static inline bool test(flag_t flags) { return ((flags & FLAG_ZF) == FLAG_ZF) || (((flags & FLAG_SF) == FLAG_SF) != ((flags & FLAG_OF) == FLAG_OF)); }
    };
    struct CondG : Condition
    {
        static inline bool test(flag_t flags) { return ((flags & FLAG_ZF) == 0) && (((flags & FLAG_SF) == FLAG_SF) == ((flags & FLAG_OF) == FLAG_OF)); }
    };
}
