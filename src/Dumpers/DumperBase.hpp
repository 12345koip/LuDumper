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
#include <unordered_map>
#include <string>
#include <cstdint>
#include <inttypes.h>
#include <stdexcept>

#define l_memberAOB static inline constexpr const char*
#define fail(msg) {puts("failure: " msg); return;}
#define log_offset(offsetStr, offset) printf(offsetStr " @ +0x%03" PRIx64 "\n", offset)

namespace LuDumper {
    namespace Dumpers {
        template<typename T> class BaseDumper {
            protected:
                std::unordered_map<T, ptrdiff_t> offsets {};

            public:
                virtual std::string ToHeaderContents() const = 0;
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