cmake_minimum_required(VERSION 3.22.1)
project(mocika_smoke C)

add_library(mocikasmoke SHARED native_probe.c)
target_link_options(mocikasmoke PRIVATE "-Wl,-z,max-page-size=16384")
target_link_libraries(mocikasmoke android)
