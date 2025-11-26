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
#define LUDUMP_ASSERT(cond, msg) {if (!!(!(cond))) fail(msg);}
#define log_finish(x) puts("\n\nFINISH: " x "\n\n")
#define debug_ins_log(ins) printf("%s %s\n", ins->mnemonic.c_str(), ins->operands.c_str())

#define decl_array(type, nelems) ("ARR " type " " nelems)
#define decl_array_align(type, nelems, align) ("ARR " type " " nelems " ALIGN " align)



inline std::string parse_decl_array(const char* arrayStr, std::string_view varName) {
    const char* typeStart = strchr(arrayStr, ' ');
    if (!typeStart) return {};
    typeStart++;

    const char* lenStart = strchr(typeStart, ' ');
    if (!lenStart) return {};
    std::string_view type(typeStart, lenStart - typeStart);

    const char* alignStart = strstr(lenStart + 1, "ALIGN");
    std::string_view len;
    std::string_view align;

    if (alignStart) {
        len = std::string_view(lenStart + 1, alignStart - (lenStart + 1));
        align = std::string_view(alignStart + 6);
    } else {
        len = std::string_view(lenStart + 1);
    }
    
    auto trim = [](std::string_view s) {
        size_t start = s.find_first_not_of(' ');
        size_t end   = s.find_last_not_of(' ');
        return (start == std::string_view::npos) ? std::string_view{} : s.substr(start, end - start + 1);
    };

    len = trim(len);
    align = trim(align);

    if (!align.empty())
        return std::format("alignas({}) {} {}[{}]", align, type, varName, len);
    else
        return std::format("{} {}[{}]", type, varName, len);
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