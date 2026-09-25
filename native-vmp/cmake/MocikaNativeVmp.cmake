include_guard(GLOBAL)

function(mocika_enable_native_vmp target)
    set(options)
    set(one_value_args PLUGIN LLVM_OPT)
    cmake_parse_arguments(MNV "${options}" "${one_value_args}" "" ${ARGN})

    if(NOT TARGET "${target}")
        message(FATAL_ERROR "mocika_enable_native_vmp: unknown target ${target}")
    endif()
    if(NOT MNV_PLUGIN OR NOT EXISTS "${MNV_PLUGIN}")
        message(FATAL_ERROR "mocika_enable_native_vmp: PLUGIN must name the built MocikaNativeVmpPass")
    endif()
    if(NOT MNV_LLVM_OPT OR NOT EXISTS "${MNV_LLVM_OPT}")
        message(FATAL_ERROR "mocika_enable_native_vmp: LLVM_OPT must name opt from the same LLVM build as the plugin")
    endif()
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang" AND
       NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "Mocika Native VMP requires Clang/LLVM")
    endif()

    get_filename_component(_mocika_vmp_root "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/.." ABSOLUTE)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    set(_mocika_vmp_launcher
        "${Python3_EXECUTABLE};${CMAKE_CURRENT_FUNCTION_LIST_DIR}/mocika_vmp_launcher.py;--opt;${MNV_LLVM_OPT};--plugin;${MNV_PLUGIN}")
    set_property(TARGET "${target}" PROPERTY C_COMPILER_LAUNCHER
        "${_mocika_vmp_launcher}")
    set_property(TARGET "${target}" PROPERTY CXX_COMPILER_LAUNCHER
        "${_mocika_vmp_launcher}")
    target_sources("${target}" PRIVATE
        "${_mocika_vmp_root}/runtime/mocika_native_vmp.c")
    target_include_directories("${target}" PRIVATE
        "${_mocika_vmp_root}/include")
    target_compile_options("${target}" PRIVATE
        "$<$<COMPILE_LANGUAGE:C,CXX>:-O2>")
    target_compile_definitions("${target}" PRIVATE MOCIKA_NATIVE_VMP_ENABLED=1)
endfunction()
