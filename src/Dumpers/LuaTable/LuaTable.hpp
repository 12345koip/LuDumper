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

        enum class LuaTableField: uint8_t {
            tt,
            marked,
            memcat,
            tmcache,
            readonly,
            safeenv,
            lsizenode,
            nodemask8,
            sizearray,
            metatable,
            array,
            node,
            gclist
        };

        constexpr const char* LuaTableFieldToString(const LuaTableField field) {
            switch (field) {
                case LuaTableField::tt:         return "tt";         
                case LuaTableField::marked:     return "marked";     
                case LuaTableField::memcat:     return "memcat";     
                case LuaTableField::tmcache:    return "tmcache";    
                case LuaTableField::readonly:   return "readonly";   
                case LuaTableField::safeenv:    return "safeenv";    
                case LuaTableField::lsizenode:  return "lsizenode";  
                case LuaTableField::nodemask8:  return "nodemask8";  
                case LuaTableField::sizearray:  return "sizearray";  
                case LuaTableField::metatable:  return "metatable";  
                case LuaTableField::array:      return "array";      
                case LuaTableField::node:       return "node";       
                case LuaTableField::gclist:     return "gclist";
                default:                        return "UNKNOWN";    
            }
        }

        enum class lt_unionField: uint8_t {
            lastfree,
            aboundary
        };

        class LuaTableDumper: public BaseDumper<LuaTableField> {
            private:
                struct UnionData {
                    std::vector<std::pair<lt_unionField, ptrdiff_t>> unionOffsets; //union offsets are from union base.
                    ptrdiff_t unionBase;
                } unionData;

                l_memberAOB setarrayvector = "48 89 74 24 ? 57 48 83 EC 30 49 63 F8 48 8B F2 81 FF ? ? ? ? 7F 7D 48 B8 ? ? ? ? ? ? ? ? 48 89 5C 24 ? 48 8B DF 48 3B F8 77 60 4C 63 42 ? 4C 8B CB 0F B6 42 02 48 8B 52 ? 49 C1 E1 04 49 C1 E0 04 88 44 24 ? E8 ? ? ? ?";
                l_memberAOB setnodevector = "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC 20 41 8B E8 48 8B DA 4C 8B F9 41 BE ? ? ? ? 45 85 C0 75 11 48 8D 05 ? ? ? ? 33 C9 48 89 42 ? 8B F1 EB 68 41 8D 48 ? E8 ? ? ? ? 8D 70 01";
                l_memberAOB luaH_new = "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 41 8B F0 8B EA 44 0F B6 41 ?? BA ?? ?? ?? ?? 48 8B F9 E8 ?? ?? ?? ?? 4C 8B 4F ?? 48 8B D8 45 0F B6 51 ?? C6 00 ?? 41 80 E2 ?? 44 88 50 ?? 44 0F B6 47 ?? 44 88 40 ??";
                l_memberAOB luaV_settable = "48 89 5C 24 ?? 48 89 6C 24 ?? 56 41 54 41 57 48 83 EC ?? 48 89 7C 24 ?? 4D 8B E1 4C 89 74 24 ?? 4D 8B F8 48 8B F2 48 8B D9 33 ED 0F 1F 44 00 00 83 7E 0C 06 75 4C";
                l_memberAOB luaT_gettmbyobj = "48 63 42 ?? 4C 8B C9 83 F8 ?? 74 ?? 83 F8 ?? 74 ?? 48 8B D0 48 8B 41 ?? 48 8B 8C D0 ?? ?? ?? ?? EB ?? 48 8B 02 48 8B 48 ?? EB ?? 48 8B 02 48 8B 48 ??";

            public:
                void Scan() override;
                std::string ToHeaderContents() override;
        };
    }
}