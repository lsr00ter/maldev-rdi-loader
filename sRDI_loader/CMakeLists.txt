cmake_minimum_required(VERSION 3.30)
project(sRDI_loader C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)

set(MASM_NAMES src/masm/peb)

# Set compiler flags to obfuscate function names (not work)
# set(CMAKE_CXX_VISIBILITY_PRESET "hidden")
# set(CMAKE_VISIBILITY_INLINES_HIDDEN "YES")
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden -g0")

include_directories(${CMAKE_SOURCE_DIR}/src/h)

FOREACH(src ${MASM_NAMES})
    SET(MASM_SRC ${CMAKE_CURRENT_SOURCE_DIR}/${src}.masm)
    SET(MASM_OBJ ${CMAKE_CURRENT_BINARY_DIR}/${src}.obj)
    ADD_CUSTOM_COMMAND(
        OUTPUT ${MASM_OBJ}
        COMMAND C:/Temp/ml64.exe /c /Fo${MASM_OBJ} ${MASM_SRC}
        DEPENDS ${MASM_SRC}
        COMMENT "Assembling ${MASM_SRC}")
    SET(MASM_OBJECTS ${MASM_OBJECTS} ${MASM_OBJ})
ENDFOREACH(src)

add_executable(sRDI_loader ${MASM_OBJECTS} main.c src/c/peb.c)

# Optimized compiler flags
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


# Set the linker flags using target_link_options (static link, remove standard system library and custom entry)
target_link_options(sRDI_loader PRIVATE
    "-static"
    "-nostdlib"
    "-Wl,--entry=start"
    "-Wl,--subsystem,windows"
)

# Add strip to remove all symbol
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_custom_command(TARGET sRDI_loader POST_BUILD
        COMMAND ${CMAKE_STRIP} --strip-all $<TARGET_FILE:sRDI_loader>
        COMMENT "Stripping symbols from executable")
endif()
