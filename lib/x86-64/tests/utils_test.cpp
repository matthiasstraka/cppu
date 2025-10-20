#include <boost/test/unit_test.hpp>

#include "x86-64_utils.h"

using namespace cpu::utils;

BOOST_AUTO_TEST_SUITE(utils_test_suite)

BOOST_AUTO_TEST_CASE(adc_u8_test)
{
    std::uint8_t accu = 0;
    BOOST_CHECK_EQUAL(false, add_with_carry(false, accu, 0x7F));
    BOOST_CHECK_EQUAL(accu, 127);
    BOOST_CHECK_EQUAL(false, add_with_carry(true, accu, 1));
    BOOST_CHECK_EQUAL(accu, 129);
    BOOST_CHECK_EQUAL(true, add_with_carry(false, accu, 128));
    BOOST_CHECK_EQUAL(accu, 1);
}

BOOST_AUTO_TEST_CASE(adc_u32_test)
{
    std::uint32_t accu = 0;
    BOOST_CHECK_EQUAL(false, add_with_carry(false, accu, 0x7F));
    BOOST_CHECK_EQUAL(accu, 127);
    BOOST_CHECK_EQUAL(false, add_with_carry(true, accu, 128));
    BOOST_CHECK_EQUAL(accu, 256);

    accu = 0xFFFFFFFF;
    BOOST_CHECK_EQUAL(false, add_with_carry(false, accu, 0));
    BOOST_CHECK_EQUAL(true,  add_with_carry(true, accu, 0));
    BOOST_CHECK_EQUAL(accu, 0);
}

BOOST_AUTO_TEST_SUITE_END()
