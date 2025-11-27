/*
This file was created by 12345koip for the
LuGo Structure Dumper, a subproject of the
LuGo executor.

See LICENSE and README for details.
*/

#pragma once
#include "Dumpers/DumperBase.hpp"

namespace LuDumper {
    namespace Dumpers {

        enum class LuauBufferField: uint8_t {
            tt,
            marked,
            memcat,
            len,
            data
        };

        constexpr const char* LuauBufferFieldToString(const LuauBufferField field) {
            switch (field) {
                case LuauBufferField::tt:     return "tt";
                case LuauBufferField::marked: return "marked";
                case LuauBufferField::memcat: return "memcat";
                case LuauBufferField::len:    return "len";
                case LuauBufferField::data:   return "data";
                default:                      return "UNKNOWN";
            }
        }


        class LuauBufferDumper: public BaseDumper<LuauBufferField> {
            private:
                l_memberAOB luaB_newbuffer = "48 89 74 24 10 57 48 83 EC 20 48 8B F2 48 8B F9 48 81 FA ?? ?? ?? ?? 77 ?? 44 0F B6 41 ?? B8 ?? ?? ?? ?? 48 3B D0 48 89 5C 24 ?? 48 0F 42 D0 48 03 D0 E8 ?? ?? ?? ?? 48 8B 4F ?? 48 8B D8 44 8B C6";
            
            public:
                void Scan() override;
                std::string ToHeaderContents() override;
        };
    }
}