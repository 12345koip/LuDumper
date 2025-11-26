cmake_minimum_required(VERSION 3.16)
project(LU_DUMPER LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED NO)
set(CMAKE_GENERATOR_PLATFORM x64)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>" CACHE STRING "" FORCE)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

foreach(OUTPUTCONFIG DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
    string(TOUPPER ${OUTPUTCONFIG} OUTPUTCONFIG_UPPER)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${OUTPUTCONFIG_UPPER} ${CMAKE_SOURCE_DIR}/bin)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${OUTPUTCONFIG_UPPER} ${CMAKE_SOURCE_DIR}/bin)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${OUTPUTCONFIG_UPPER} ${CMAKE_BINARY_DIR}/lib)
endforeach()

add_library(LU_DUMPER SHARED
    src/Entry.cpp
    src/Misc/Dissassembler/Dissassembler.cpp
    src/Dumpers/LuaState/LuaState.cpp
    src/Dumpers/TValue/TValue.cpp
    src/Dumpers/TString/TString.cpp
    src/Dumpers/Udata/Udata.cpp
    src/Misc/FileBits/FileBits.cpp
)



target_include_directories(LU_DUMPER PUBLIC
    ${CMAKE_SOURCE_DIR}/src/Dependencies
    ${CMAKE_SOURCE_DIR}/src/
)


target_link_libraries(LU_DUMPER PUBLIC
    libhat capstone DbgHelp
)

get_target_property(type LU_DUMPER TYPE)
message(STATUS "Target type = ${type}")


target_compile_definitions(LU_DUMPER PUBLIC NOMINMAX WIN32_LEAN_AND_MEAN)

add_subdirectory(${CMAKE_SOURCE_DIR}/src/Dependencies/libhat)
add_subdirectory(${CMAKE_SOURCE_DIR}/src/Dependencies/Capstone)

target_compile_options(LU_DUMPER PRIVATE
    $<$<CONFIG:Debug>:/MTd>
    $<$<CONFIG:Release>:/MT>
)