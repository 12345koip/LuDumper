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

        enum class UdataField: uint8_t {
            tt,
            marked,
            memcat,
            tag,
            len,
            metatable,
            data
        };

        constexpr const char* UdataFieldToString(const UdataField field) {
            switch (field) {
                case UdataField::tt:        return "tt";
                case UdataField::marked:    return "marked";
                case UdataField::memcat:    return "memcat";
                case UdataField::tag:       return "tag";
                case UdataField::len:       return "len";
                case UdataField::metatable: return "metatable";
                case UdataField::data:      return "data";
                default:                    return "UNKNOWN";
            }
        }


        class UdataDumper: public BaseDumper<UdataField> {
            private:
                l_memberAOB luaU_newudata = "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 41 8B F0 48 8B DA 48 8B F9 48 81 FA ?? ?? ?? ?? 77 ?? 48 83 FA 10 76 ?? 48 83 C2 0F 48 83 E2 F0 44 0F B6 41 ?? 48 83 C2 10 E8 ?? ?? ?? ?? 48 8B 4F ?? 0F B6 51 ?? 80 E2 03 C6 00 08";

            public:
                void Scan() override;
                std::string ToHeaderContents() override;
        };
    }
}