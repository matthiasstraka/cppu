#pragma once

#include <cstdint>
#include <type_traits>

#if defined(__MACHINEX86_X64) || defined(__x86_64__)
#define HAS_INTRIN_ADC
#include <immintrin.h>
#endif

namespace cpu::utils
{
    template<typename T>
    void set_bit(T& value, std::size_t mask, bool set)
    {
        if (set)
        {
            value |= mask;
        }
        else
        {
            value &= ~mask;
        }
    }

    inline bool add_with_carry(bool carry, std::uint8_t& target, std::uint8_t value)
    {
#ifdef _MSC_VER
        return _addcarry_u8(carry, target, value, &target);
#else
        uint8_t sum = target + value + static_cast<std::uint8_t>(carry);
        uint8_t c = static_cast<std::uint8_t>((target & value) ^ ((target ^ value) & ~sum));
        target = sum;
        return (c & 0x80) == 0x80;
#endif
    }

    inline bool add_with_carry(bool carry, std::uint16_t& target, std::uint16_t value)
    {
#ifdef _MSC_VER
        return _addcarry_u16(carry, target, value, &target);
#else
        uint16_t sum = target + value + static_cast<std::uint16_t>(carry);
        uint16_t c = static_cast<std::uint16_t>((target & value) ^ ((target ^ value) & ~sum));
        target = sum;
        return (c & 0x8000) == 0x8000;
#endif
    }

    inline bool add_with_carry(bool carry, std::uint32_t& target, std::uint32_t value)
    {
#ifdef HAS_INTRIN_ADC
        return _addcarry_u32(carry, target, value, &target);
#else
        uint32_t sum = target + value + static_cast<std::uint32_t>(carry);
        uint32_t c = static_cast<std::uint32_t>((target & value) ^ ((target ^ value) & ~sum));
        target = sum;
        return (c & 0x80000000) == 0x80000000;
#endif
    }

    inline bool add_with_carry(bool carry, std::uint64_t& target, std::uint64_t value)
    {
#ifdef HAS_INTRIN_ADC
        return _addcarry_u64(carry, target, value, reinterpret_cast<unsigned long long*>(&target));
#else
        uint64_t sum = target + value + static_cast<std::uint64_t>(carry);
        uint64_t c = static_cast<std::uint32_t>((target & value) ^ ((target ^ value) & ~sum));
        target = sum;
        return (c & 0x8000000000000000ull) == 0x8000000000000000ull;
#endif
    }
}
