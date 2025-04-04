cmake_minimum_required(VERSION 3.30)
project(sRDI_loader src/c)

set(CMAKE_C_STANDARD 17)
set(MASM_NAMES src/masm/peb)

include_directories(${CMAKE_SOURCE_DIR}/src/h)

FOREACH (src ${MASM_NAMES})
    SET(MASM_SRC ${CMAKE_CURRENT_SOURCE_DIR}/${src}.masm)
    SET(MASM_OBJ ${CMAKE_CURRENT_BINARY_DIR}/${src}.obj)
    ADD_CUSTOM_COMMAND(
            OUTPUT ${MASM_OBJ}
            COMMAND C:/Temp/ml64.exe /c /Fo${MASM_OBJ} ${MASM_SRC}
            DEPENDS ${MASM_SRC}
            COMMENT "Assembling ${MASM_SRC}")
    SET(MASM_OBJECTS ${MASM_OBJECTS} ${MASM_OBJ})
ENDFOREACH (src)

add_executable(sRDI_loader ${MASM_OBJECTS} main.c src/c/peb.c)

# Set compiler flags to obfuscate function names
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden -g0")

# 指定需要链接的库
target_link_libraries(sRDI_loader PRIVATE
        -Wl,--start-group
        msvcrt.a
        -Wl,--end-group
)

# Define compiler flags as a space-separated string
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} \
    -O2 \
    -Wall \
    -Wextra \
    -Wformat \
    -Wformat-security \
    -Wconversion \
")

# Security definitions
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} \
    -D_FORTIFY_SOURCE=2 \
    -DDYNAMIC_BASE \
    -DNXCOMPAT \
")

# Windows linker flags
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} \
    -Wl,--nxcompat \
    -Wl,--dynamicbase \
    -Wl,--no-seh \
")

target_link_options(sRDI_loader PRIVATE -static -nostdlib)
set_target_properties(sRDI_loader PROPERTIES LINK_FLAGS "-e start")
