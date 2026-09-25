cmake_minimum_required(VERSION 3.22.1)
project(mocika_conditional_feature C)

add_library(mocikaconditional SHARED conditional_probe.c)
target_link_options(mocikaconditional PRIVATE "-Wl,-z,max-page-size=16384")

if(MOCIKA_NATIVE_VMP_ROOT AND MOCIKA_NATIVE_VMP_PLUGIN AND MOCIKA_NATIVE_VMP_OPT)
    include("${MOCIKA_NATIVE_VMP_ROOT}/cmake/MocikaNativeVmp.cmake")
    mocika_enable_native_vmp(mocikaconditional
        PLUGIN "${MOCIKA_NATIVE_VMP_PLUGIN}"
        LLVM_OPT "${MOCIKA_NATIVE_VMP_OPT}")
endif()
