cmake_minimum_required(VERSION 3.30)
project(dll_poc C)

set(CMAKE_C_STANDARD 17)

# add_executable(dll_poc main.c)

set(CMAKE_SHARED_LIBRARY_PREFIX "")
add_library(dll_poc SHARED main.c)