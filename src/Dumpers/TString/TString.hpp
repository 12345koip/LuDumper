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

        enum class TStringField: uint8_t {
            tt,
            marked,
            memcat,
            atom,
            next,
            hash,
            len,
            data
        };


        constexpr const char* TStringFieldToString(const TStringField field) {
            switch (field) {
                case TStringField::tt:     return "tt";
                case TStringField::marked: return "marked";
                case TStringField::memcat: return "memcat";
                case TStringField::atom:   return "atom";
                case TStringField::next:   return "next";
                case TStringField::hash:   return "hash";
                case TStringField::len:    return "len";
                case TStringField::data:   return "data";
                default:                   return "UNKNOWN";
            }
        }

        class TStringDumper: public BaseDumper<TStringField> {
            private:
                l_memberAOB luaS_newlstr = "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 48 83 EC ?? 48 8B F2 48 8B E9 48 8B CE 49 8B D0 49 8B F8 E8 ?? ?? ?? ?? 4C 8B 75 ?? 4C 63 C8 44 8B F8 4D 63 56 ?? 49 8B 5E ?? 49 FF CA 4D 23 D1 4A 8B 1C D3 48 85 DB 74 ?? 0F 1F 00 8B 43 ?? 48 3B C7 75 ?? 48 8D 53 ?? 4C 8B C7 48 8B CE E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 5B ??";

            public:
                void Scan() override;
                std::string ToHeaderContents() override;
        };
    }
}