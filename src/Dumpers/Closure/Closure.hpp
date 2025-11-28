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

        enum class l_unionField: uint8_t {
            p,
            uprefs
        };

        enum class c_unionField: uint8_t {
            f,
            cont,
            debugname,
            upvals
        };

        enum class ClosureField: uint8_t {
            tt,
            marked,
            memcat,
            isC,
            nupvalues,
            stacksize,
            preload,
            gclist,
            env,
            __union
        };

        
        constexpr const char* ClosureFieldToString(const ClosureField field) {
            switch (field) {
                case ClosureField::tt:        return "tt";        
                case ClosureField::marked:    return "marked";    
                case ClosureField::memcat:    return "memcat";    
                case ClosureField::isC:       return "isC";       
                case ClosureField::nupvalues: return "nupvalues"; 
                case ClosureField::stacksize: return "stacksize"; 
                case ClosureField::preload:   return "preload";   
                case ClosureField::gclist:    return "gclist";    
                case ClosureField::env:       return "env";       
                default:                      return "unknown";  
            }
        }

        constexpr const char* CUnionFieldToString(const c_unionField field) {
            switch (field) {
                case c_unionField::f:         return "f";
                case c_unionField::cont:      return "cont";
                case c_unionField::debugname: return "debugname";
                case c_unionField::upvals:    return "upvals";
                default: return "UNKNOWN";
            }
        }

        constexpr const char* LUnionFieldToString(const l_unionField field) {
            switch (field) {
                case l_unionField::uprefs: return "uprefs";
                case l_unionField::p:      return "p";
                default: return "UNKNOWN";
            }
        }

        class ClosureDumper: public BaseDumper<ClosureField> {
            private:
                struct UnionData { //offsets are from the base offset of the union, not the closure base.
                    std::vector<std::pair<l_unionField, ptrdiff_t>> lClosureFields = {};
                    std::vector<std::pair<c_unionField, ptrdiff_t>> cClosureFields = {};
                    ptrdiff_t unionOffset;
                } unionData;



                l_memberAOB luaF_newCclosure = "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 63 F2 49 8B F8 44 0F B6 41 ?? 48 8B D9 48 8D 56 ?? 48 C1 E2 ?? E8 ?? ?? ?? ?? 4C 8B 4B ?? 45 0F B6 41 ?? 41 80 E0 ?? C6 00 ?? 44 88 40 ?? 0F B6 4B ?? 48 8B 5C 24 ?? 88 48 ?? 33 C9 40 88 70 ?? 48 8B 74 24 ?? 48 89 48 ?? 48 89 48 ??";
                l_memberAOB lua_pushcclosurek = "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B D9 49 63 F9 48 8B 49 ?? 49 8B F0 48 8B EA 48 8B 41 ?? 48 39 41 ?? 72 ?? B2 ?? 48 8B CB E8 ?? ?? ?? ?? F6 43 ?? ?? 74 ?? 4C 8D 43 ?? 48 8B D3 48 8B CB E8 ?? ?? ?? ?? 48 8B 43 ?? 48 3B 43 ?? 75 ?? 4C 8B 43 ?? EB ?? 48 8B 40 ?? 48 8B 08 4C 8B 41 ?? 8B D7 48 8B CB E8 ?? ?? ?? ??";
                l_memberAOB luaF_newLclosure = "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 8B EA 49 8B F8 44 0F B6 41 ?? 49 8B F1 48 63 D2 48 8B D9 48 83 C2 02 48 C1 E2 04 E8 ?? ?? ?? ?? 4C 8B 4B ?? 4C 8B D0 45 0F B6 41 ?? 41 80 E0 03 C6 00 07 44 88 40 01 0F B6 4B ?? 88 48 ?? C6 40 ?? 00 48 89 78 ??";

                const std::string CUnionToHeader();
                const std::string LUnionToHeader();

            public:
                void Scan() override;
                std::string ToHeaderContents() override;
        };
    }
}