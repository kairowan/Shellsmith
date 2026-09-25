cmake_minimum_required(VERSION 3.20)
project(MocikaNativeVmpFixture LANGUAGES C)

if(NOT MOCIKA_NATIVE_VMP_PLUGIN)
    message(FATAL_ERROR "MOCIKA_NATIVE_VMP_PLUGIN is required")
endif()
if(NOT MOCIKA_NATIVE_VMP_OPT)
    message(FATAL_ERROR "MOCIKA_NATIVE_VMP_OPT is required")
endif()

include("${CMAKE_CURRENT_LIST_DIR}/../../cmake/MocikaNativeVmp.cmake")
add_executable(mocika-native-vmp-fixture main.c)
mocika_enable_native_vmp(mocika-native-vmp-fixture
    PLUGIN "${MOCIKA_NATIVE_VMP_PLUGIN}"
    LLVM_OPT "${MOCIKA_NATIVE_VMP_OPT}")
