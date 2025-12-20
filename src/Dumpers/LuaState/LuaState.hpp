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

        constexpr const char* LuaStateFieldToString(const LuaStateField field) {
            switch (field) {
                case LuaStateField::tt:           return "tt";
                case LuaStateField::marked:       return "marked";
                case LuaStateField::memcat:       return "memcat";
                case LuaStateField::status:       return "status";
                case LuaStateField::activememcat: return "activememcat";
                case LuaStateField::isactive:     return "isactive";
                case LuaStateField::singlestep:   return "singlestep";
                case LuaStateField::top:          return "top";
                case LuaStateField::base:         return "base";
                case LuaStateField::global:       return "global";
                case LuaStateField::ci:           return "ci";
                case LuaStateField::stack_last:   return "stack_last";
                case LuaStateField::stack:        return "stack";
                case LuaStateField::end_ci:       return "end_ci";
                case LuaStateField::base_ci:      return "base_ci";
                case LuaStateField::stacksize:    return "stacksize";
                case LuaStateField::size_ci:      return "size_ci";
                case LuaStateField::nCcalls:      return "nCcalls";
                case LuaStateField::baseCcalls:   return "baseCcalls";
                case LuaStateField::cachedslot:   return "cachedslot";
                case LuaStateField::gt:           return "gt";
                case LuaStateField::openupval:    return "openupval";
                case LuaStateField::gclist:       return "gclist";
                case LuaStateField::namecall:     return "namecall";
                case LuaStateField::userdata:     return "userdata";
                default:                          return "UNKNOWN";
            }
        }


        class LuaStateDumper: public BaseDumper<LuaStateField> {
            private:
                l_memberAOB stack_init = "48 89 5C 24 08 57 48 83 EC 20 44 0F B6 41 02 48 8B DA 48 8B F9 BA 40 01 00 00 48 8B CB E8 ?? ?? ?? ??";
                l_memberAOB luaE_newthread = "48 89 5C 24 ?? 57 48 83 EC ?? 44 0F B6 41 ?? BA ?? ?? ?? ?? 48 8B F9 E8 ?? ?? ?? ?? 48 8B 57 ?? 48 8B D8 44 0F B6 42 ?? C6 00 ?? 41 80 E0 ?? 44 88 40 ??";
                l_memberAOB lua_newthread = "48 89 5c 24 ?? 57 48 83 ec ?? 48 8b 51 ?? 48 8b d9 48 8b 42 ?? 48 39 42 ?? 72 ?? b2 ?? e8 ?? ?? ?? ?? f6 43 ?? ?? 74 ?? 4c 8d 43 ?? 48 8b d3 48 8b cb e8 ?? ?? ?? ?? 48 8b cb e8 ?? ?? ?? ?? 48 8b 4b ?? 48 8b f8 48 89 01 c7 41 ?? ?? ?? ?? ?? 48 83 43 ?? ??";
                l_memberAOB luaV_gettable = "48 89 5c 24 ?? 55 41 54 41 55 41 56 41 57 48 83 ec ?? 48 89 74 24 ?? 4c 8d 2d ?? ?? ?? ?? 48 89 7c 24 ?? 4d 8b e1 4d 8b f8 48 8b da 4c 8b f1 33 ed 83 7b ?? ?? 75 ?? 48 8b 33 49 8b d7 48 8b ce e8 ?? ?? ?? ?? 48 8b f8 49 3b c5 74 ?? 48 8b c8 48 2b 4e ?? 48 c1 f9 ?? 41 89 4e ?? 83 78 ?? ?? 75 ?? 48 8b 4e ?? 48 85 c9 74 ?? f6 41 ?? ?? 75 ?? 4d 8b 46 ??";
                l_memberAOB luaD_call = "40 53 57 48 83 EC ?? 0F B7 41 ?? 48 8B D9 66 FF C0 49 63 F8 66 89 41 ?? 4C 8B CA B9 ?? ?? ?? ?? 66 3B C1 72 ?? 0F 84 ?? ?? ?? ?? B9 ?? ?? ?? ?? 66 3B C1 0F 83 ?? ?? ?? ?? 48 8B 53 ?? 48 89 74 24 ?? 48 8B 73 ?? 4C 89 74 24 ?? 45 32 F6 4C 89 7C 24 ?? 48 3B F2 74 ?? 48 8B 46 ?? 48 8B 08 44 38 71 ?? 74 ?? 48 83 79 ?? ?? 74 ?? 66 FF 43 ?? 41 B6 ?? 4D 8B F9 48 2B F2 4C 2B 7B ?? 49 8B D1 44 8B C7 48 8B CB E8 ?? ?? ?? ?? 85 C0 75 ?? 48 8B 43 ?? 48 89 6C 24 ?? 83 48 24 ?? F6 43 ?? ?? 0F B6 6B ?? C6 43 ?? ?? 74 ?? 4C 8D 43 ?? 48 8B D3 48 8B CB E8 ?? ?? ?? ??";
                l_memberAOB luaD_reallocstack = "48 89 5C 24 ?? 55 48 83 EC ?? 48 63 EA 48 8B D9 81 FD ?? ?? ?? ?? 0F 8F ?? ?? ?? ?? 48 89 74 24 ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 8B 71 ?? 48 89 7C 24 ?? 4C 89 74 24 ?? 44 8D 75 ?? 49 63 FE 48 3B F8 0F 87 ?? ?? ?? ?? 4C 63 41 ?? 4C 8B CF 0F B6 41 ?? 48 8B D6 49 C1 E1 ?? 49 C1 E0 ?? 88 44 24 ?? E8 ?? ?? ?? ?? 4C 63 43 ?? 4C 8B C8 48 89 43 ?? 48 8B D0 4C 3B C7 7D ?? 49 8B D0 49 2B F8 48 C1 E2 ?? 48 83 C2 ?? 48 03 D0 33 C0 66 90 89 02 48 8D 52 ?? 48 83 EF ?? 75 F4 48 8B 53 ?? 48 8B 4B ?? 48 8B C5 48 C1 E0 ?? 49 03 C1 44 89 73 ?? 48 89 43 ??";
                l_memberAOB currfuncname = "48 89 5c 24 08 57 48 83 ec 20 48 8b 41 40 48 8b f9 48 3b 41 70 76 4a 48 8b 40 10 48 8b 18 48 85 db 74 3e 80 7b 03 00 74 38 48 8b 5b 20 48 85 db 74 31 48 8d 15 ?? ?? ?? ?? 48 8b cb e8 ?? ?? ?? ?? 85 c0 75 1e 48 8b 4f 10 33 db 48 85 c9 48 8d 41 18 48 0f 44 c3 48 8b 5c 24 30 48 83 c4 20 5f c3";

            public:
                std::string ToHeaderContents() override;
                void Scan() override;
        };
    }
}