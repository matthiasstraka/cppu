#include <boost/test/unit_test.hpp>

#include "elf_file.h"

using elf::ElfFile64;

BOOST_AUTO_TEST_SUITE(elf_suite)

BOOST_AUTO_TEST_CASE(default_test)
{
    ElfFile64 file(TEST_FILES_PATH "simple/simple.bin");
    BOOST_REQUIRE_EQUAL(file.getNumProgramSections(), 11);
    BOOST_CHECK_EQUAL(file.getString(1), ".symtab");
}

BOOST_AUTO_TEST_SUITE_END()
