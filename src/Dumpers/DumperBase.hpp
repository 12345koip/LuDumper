/*
This file was created by 12345koip for the
LuGo Structure Dumper, a subproject of the
LuGo executor.

See LICENSE and README for details.
*/

#pragma once
#include "Misc/Dissassembler/Dissassembler.hpp"
#include "libhat/include/libhat.hpp"
#include "libhat/include/libhat/scanner.hpp"
#include "libhat/include/libhat/signature.hpp"
#include "Misc/FileBits/FileBits.hpp"
#include <vector>
#include <string>
#include <cstdint>
#include <inttypes.h>
#include <stdexcept>
#include <sstream>
#include <algorithm>
#include <format>

#define l_memberAOB static inline constexpr const char*
#define fail(msg) {puts("failure: " msg); return;}
#define log_offset(offsetStr, offset) printf("%s @ +0x%03" PRIx64 "\n", offsetStr, offset)
#define log_search(insn) puts("Finding instruction: \"" insn "\"")
#define LUDUMP_ASSERT(cond, msg) {if (!!(cond)) fail(msg);}
#define log_finish(x) puts("\n\nFINISH: " x "\n\n")

#define decl_array(type, nelems) ("ARR " type " " nelems)

inline const char* parse_decl_array(const char* arrayStr, std::string_view varName) {
    static std::string result;

    const char* typeStart = strchr(arrayStr, ' ');
    if (!typeStart) return nullptr;
    typeStart++;

    const char* lenStart = strchr(typeStart, ' ');
    if (!lenStart) return nullptr;

    std::string_view type (typeStart, lenStart - typeStart);
    std::string_view len (lenStart + 1);

    result = std::format("{} {}[{}]", type, varName, len);
    return result.c_str();
}





namespace LuDumper {
    namespace Dumpers {
        template<typename T> class BaseDumper {
            protected:
                //vector with pair so entries can be easily sorted.
                std::vector<std::pair<T, ptrdiff_t>> offsets {};

            public:
                virtual std::string ToHeaderContents() = 0;
                virtual void Scan() = 0;
                
                inline ptrdiff_t GetOffset(const T& fieldName) const {
                    if (!this->offsets.contains(fieldName))
                        throw std::runtime_error("attempt to read missing field offset");
                    
                    return this->offsets.at(fieldName);
                }

                inline bool HasOffset(const T& fieldName) const {
                    return this->offsets.contains(fieldName);
                }
        };
    }
}