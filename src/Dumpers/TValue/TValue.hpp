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
        
        enum class TValueField: uint8_t {
            value,
            extra,
            tt
        };


        constexpr const char* TValueFieldToString(const TValueField field) {
            switch (field) {
                case TValueField::extra: return "extra";
                case TValueField::value: return "value";
                case TValueField::tt:    return "tt";
                default:                 return "UNKNOWN";
            }
        };


        class TValueDumper: public BaseDumper<TValueField> {
            private:
                l_memberAOB luaT_gettmbyobj = "48 63 42 ?? 4C 8B C9 83 F8 ?? 74 ?? 83 F8 ?? 74 ?? 48 8B D0 48 8B 41 ?? 48 8B 8C D0 ?? ?? ?? ?? EB ?? 48 8B 02 48 8B 48 ?? EB ?? 48 8B 02 48 8B 48 ??";

            public:
                std::string ToHeaderContents() override;
                void Scan() override;
        };
    }
}