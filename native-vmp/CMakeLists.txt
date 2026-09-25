cmake_minimum_required(VERSION 3.20)
project(MocikaNativeVmpPass LANGUAGES C CXX)

find_package(LLVM REQUIRED CONFIG)
if(NOT LLVM_VERSION_MAJOR EQUAL 21)
    message(FATAL_ERROR "Mocika Native VMP requires LLVM 21, found ${LLVM_PACKAGE_VERSION}")
endif()
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)

add_llvm_pass_plugin(MocikaNativeVmpPass
    src/MocikaNativeVmpPass.cpp
)

target_compile_features(MocikaNativeVmpPass PRIVATE cxx_std_17)
target_include_directories(MocikaNativeVmpPass PRIVATE ${LLVM_INCLUDE_DIRS})
target_compile_definitions(MocikaNativeVmpPass PRIVATE ${LLVM_DEFINITIONS})
