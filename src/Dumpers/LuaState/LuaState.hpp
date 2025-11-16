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

        enum class LuaStateField: uint8_t {
            tt,
            marked,
            memcat,
            status,
            activememcat,
            isactive,
            singlestep,
            top,
            base,
            global,
            ci,
            stack_last,
            stack,
            end_ci,
            base_ci,
            stacksize,
            size_ci,
            nCcalls,
            baseCcalls,
            cachedslot,
            gt,
            openupval,
            gclist,
            namecall,
            userdata
        };

        class LuaStateDumper: public BaseDumper<LuaStateField> {
            private:
                l_memberAOB stack_init = "48 89 5C 24 08 57 48 83 EC 20 44 0F B6 41 02 48 8B DA 48 8B F9 BA 40 01 00 00 48 8B CB E8 ?? ?? ?? ??";
                l_memberAOB luaE_newthread = "48 89 5C 24 ?? 57 48 83 EC ?? 44 0F B6 41 ?? BA ?? ?? ?? ?? 48 8B F9 E8 ?? ?? ?? ?? 48 8B 57 ?? 48 8B D8 44 0F B6 42 ?? C6 00 ?? 41 80 E0 ?? 44 88 40 ??";

            public:
                std::string ToHeaderContents() const override;
                void Scan() override;
        };
    }
}