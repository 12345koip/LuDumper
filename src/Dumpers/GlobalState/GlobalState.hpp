/*
This file was created by 12345koip for the
LuGo Structure Dumper, a subproject of the
LuGo executor.

See LICENSE and README for details.
*/

#pragma once
#include "Dumpers/DumperBase.hpp"
#include "Dumpers/TValue/TValue.hpp"

namespace LuDumper {
    namespace Dumpers {

        enum class GlobalStateField: uint8_t {
            strt,
            frealloc,
            ud,
            currentwhite,
            gcstate,
            gray,
            grayagain,
            weak,
            GCthreshold,
            totalbytes,
            gcgoal,
            gcstepmul,
            gcstepsize,
            freepages,
            freegcopages,
            allpages,
            allgcopages,
            sweepgcopage,
            memcatbytes,
            mainthread,
            uvhead,
            mt,
            ttname,
            tmname,
            pseudotemp,
            registry,
            registryfree,
            errorjmp,
            rngstate,
            ptrenckey,
            cb,
            ecb,
            udatagc,
            udatamt,
            lightuserdataname,
            gcstats,
            gcmetrics
        };

        enum class cbField: uint8_t {
            userdata,
            interrupt,
            panic,
            userthread,
            useratom,
            debugbreak,
            debugstep,
            debuginterrupt,
            debugprotectederror,
            onallocate
        };

        enum class stringtableField: uint8_t { //we will dump stringtable with the global_State.
            hash,
            nuse,
            size
        };

        enum class ExecCallbacksField: uint8_t {
            context,
            close,
            destroy,
            enter,
            disable,
            getmemorysize,
            gettypemapping
        };

        enum class CallbacksField: uint8_t {
            userdata,
            interrupt,
            panic,
            userthread,
            useratom,
            debugbreak,
            debugstep,
            debuginterrupt,
            debugprotectederror,
            onallocate
        };

        constexpr const char* cbFieldToString(const cbField field) {
            switch (field) {
                case cbField::debugbreak:          return "debugbreak";
                case cbField::debugstep:           return "debugstep";
                case cbField::debuginterrupt:      return "debuginterrupt";
                case cbField::debugprotectederror: return "debugprotectederror";
                case cbField::onallocate:          return "onallocate";
                case cbField::userthread:          return "userthread";
                case cbField::useratom:            return "useratom";
                case cbField::userdata:            return "userdata";
                case cbField::interrupt:           return "interrupt";
                case cbField::panic:               return "panic";
                default:                           return "UNKNOWN";
            }
        }

        constexpr const char* GlobalStateFieldToString(const GlobalStateField field) {
            switch (field) {
                case GlobalStateField::strt:               return "strt";                
                case GlobalStateField::frealloc:           return "frealloc";            
                case GlobalStateField::ud:                 return "ud";                 
                case GlobalStateField::currentwhite:       return "currentwhite";       
                case GlobalStateField::gcstate:            return "gcstate";            
                case GlobalStateField::gray:               return "gray";               
                case GlobalStateField::grayagain:          return "grayagain";          
                case GlobalStateField::weak:               return "weak";               
                case GlobalStateField::GCthreshold:        return "GCthreshold";        
                case GlobalStateField::totalbytes:         return "totalbytes";         
                case GlobalStateField::gcgoal:             return "gcgoal";             
                case GlobalStateField::gcstepmul:          return "gcstepmul";          
                case GlobalStateField::gcstepsize:         return "gcstepsize";         
                case GlobalStateField::freepages:          return "freepages";          
                case GlobalStateField::freegcopages:       return "freegcopages";       
                case GlobalStateField::allpages:           return "allpages";           
                case GlobalStateField::allgcopages:        return "allgcopages";        
                case GlobalStateField::sweepgcopage:       return "sweepgcopage";       
                case GlobalStateField::memcatbytes:        return "memcatbytes";        
                case GlobalStateField::mainthread:         return "mainthread";         
                case GlobalStateField::uvhead:             return "uvhead";
                case GlobalStateField::mt:                 return "mt";             
                case GlobalStateField::ttname:             return "ttname";             
                case GlobalStateField::tmname:             return "tmname";             
                case GlobalStateField::pseudotemp:         return "pseudotemp";         
                case GlobalStateField::registry:           return "registry";           
                case GlobalStateField::registryfree:       return "registryfree";       
                case GlobalStateField::errorjmp:           return "errorjmp";           
                case GlobalStateField::rngstate:           return "rngstate";           
                case GlobalStateField::ptrenckey:          return "ptrenckey";          
                case GlobalStateField::cb:                 return "cb";                 
                case GlobalStateField::ecb:                return "ecb";                
                case GlobalStateField::udatagc:            return "udatagc";            
                case GlobalStateField::udatamt:            return "udatamt";            
                case GlobalStateField::lightuserdataname:  return "lightuserdataname";  
                case GlobalStateField::gcstats:            return "gcstats";            
                case GlobalStateField::gcmetrics:          return "gcmetrics";          
                default:                                   return "unknown";            
            }
        }

        constexpr const char* StringTableFieldToString(const stringtableField field) {
            switch (field) {
                case stringtableField::hash:  return "hash";  
                case stringtableField::nuse:  return "nuse";  
                case stringtableField::size:  return "size";  
                default:                      return "unknown";
            }
        }

        constexpr const char* ExecCallbacksFieldToString(const ExecCallbacksField field) {
            switch (field) {
                case ExecCallbacksField::context:          return "context";          
                case ExecCallbacksField::close:            return "close";            
                case ExecCallbacksField::destroy:          return "destroy";          
                case ExecCallbacksField::enter:            return "enter";            
                case ExecCallbacksField::disable:          return "disable";          
                case ExecCallbacksField::getmemorysize:    return "getmemorysize";    
                case ExecCallbacksField::gettypemapping:   return "gettypemapping";   
                default:                                   return "unknown";          
            }
        }

        constexpr const char* CallbacksFieldToString(const CallbacksField field) {
            switch (field) {
                case CallbacksField::userdata:              return "userdata";              
                case CallbacksField::interrupt:             return "interrupt";             
                case CallbacksField::panic:                 return "panic";                 
                case CallbacksField::userthread:            return "userthread";            
                case CallbacksField::useratom:              return "useratom";              
                case CallbacksField::debugbreak:            return "debugbreak";            
                case CallbacksField::debugstep:             return "debugstep";             
                case CallbacksField::debuginterrupt:        return "debuginterrupt";        
                case CallbacksField::debugprotectederror:   return "debugprotectederror";   
                case CallbacksField::onallocate:            return "onallocate";            
                default:                                    return "unknown";               
            }
        }

        class GlobalStateDumper: public BaseDumper<GlobalStateField> {
            private:
                TValueDumper* tvDumper = nullptr;

                l_memberAOB luaS_newlstr = "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 48 83 EC ?? 48 8B F2 48 8B E9 48 8B CE 49 8B D0 49 8B F8 E8 ?? ?? ?? ?? 4C 8B 75 ?? 4C 63 C8 44 8B F8 4D 63 56 ?? 49 8B ?? ?? 49 ?? ?? ?? ??";
                l_memberAOB luaC_step = "48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 57 41 56 41 57 48 83 ec 30 48 8b 59 ?? b8 1f 85 eb 51 0f b6 f2 0f 29 74 24 20 4c 8b f1 44 8b 43 ?? 44 0f af 43 ?? 48 8b 6b ?? 48 2b 6b ?? 41 f7 e8 8b fa c1 ff 05 8b c7 c1 e8 1f 03 f8 48 8b 83 ?? ?? ?? ?? 48 85 c0 74 04 33 d2 ff d0 0f b6 43 ?? 84 c0 75 32 e8 ?? ?? ?? ?? 0f b6 43 ?? f2 0f 11 83 ?? ?? ?? ?? 84 c0 75 1d e8 ?? ?? ?? ?? f2 0f 11 83 ?? ?? ?? ?? f2 0f 5c 83 ?? ?? ?? ??";
                l_memberAOB luaC_fullGC = "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B 59 ?? 48 8B F9 0F B6 4B ?? 84 C9 75 ?? E8 ?? ?? ?? ?? 0F B6 4B ?? F2 0F 11 83 ?? ?? ?? ?? F2 0F 5C 83 ?? ?? ?? ?? F2 0F 11 83 ?? ?? ?? ?? 8D 41 ?? 33 ED 3C ?? 76 ?? 84 C9 74 ?? EB ?? 48 8B 83 ?? ?? ?? ?? 48 89 83 ?? ?? ?? ?? 48 89 6B ?? 48 89 6B ?? 48 89 6B ?? C6 43 ?? ?? 48 C7 C2 ?? ?? ?? ?? 48 8B CF E8 ?? ?? ?? ?? 40 38 6B ?? 75 ?? 48 8B 43 ?? 48 8D 4B ?? ?? ?? ?? ??";
                l_memberAOB luaM_new = "48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 48 89 7c 24 20 41 56 48 83 ec 20 48 8b 79 48 48 8d 42 ff 45 0f b6 f0 48 8b da 48 8b f1 48 3d 00 04 00 00 73 ?? 48 8d 05 ?? ?? ?? ?? 0f be 14 02 85 d2 78 ?? e8 ?? ?? ?? ?? eb ?? 48 8b 47 ?? 4c 8b cb 48 8b 4f ??";
                l_memberAOB freeblock = "4C 8B 51 ?? 49 83 E8 08 44 8B CA 4C 8B D9 49 8B 10 48 83 7A 28 00 75 ?? 83 7A 30 00 7D ?? 49 63 C1 49 8D 0C C2 48 8B 81 ?? ?? ?? ?? 48 89 42 08 48 85 C0 74 ?? 48 89 10 48 89 91 ?? ?? ?? ??";
                l_memberAOB luaT_objtypename = "48 89 5C 24 ?? 57 48 83 EC ?? 48 8B DA 48 8B F9 48 63 52 ?? 83 FA ?? 75 ?? 48 8B 03 80 78 ?? ?? 74 ?? 48 8B 48 ?? 48 85 C9 74 ?? 48 8B 57 ?? 48 8B 92 ?? ?? ?? ?? EB ?? 83 FA ?? 75 ?? 48 63 43 ?? 3D ?? ?? ?? ?? 73 ?? 48 8B C8 48 8B 47 ?? 48 8B 84 C8 ?? ?? ?? ?? 48 85 C0 75 ?? 4C 8B 47 ?? 49 8B 8C D0 ?? ?? ?? ?? 48 85 C9 74 ?? 49 8B 90 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 78 ?? ?? 75 ?? 48 8B 00 48 83 C0 ?? 48 8B 5C 24 ?? 48 83 C4 ?? 5F C3";
                l_memberAOB pseudo2addr = "41 b9 ee d8 ff ff 4c 8b c1 41 3b d1 0f 84 88 00 00 00 81 fa ef d8 ff ff 74 45 81 fa f0 d8 ff ff 74 32 48 8b 41 40 44 2b ca 48 8b 48 ?? 4c 8b 01 41 0f b6 40 05 44 3b c8 7f 12 41 8d 41 ff 48 98 48 83 c0 03 48 c1 e0 04";
                l_memberAOB math_random = "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B 71 ?? 48 8B D9 E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B CB 83 E8 ?? 0F 84 ?? ?? ?? ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? 8B D0 E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 8B CB 8B";
                l_memberAOB lua_encodepointer = "4C 8B 41 ?? 48 8B C2 49 0F AF 80 ?? ?? ?? ?? 49 0F AF 90 ?? ?? ?? ?? 49 03 80 ?? ?? ?? ?? 49 03 90 ?? ?? ?? ?? 48 33 C2 C3";
                l_memberAOB newUserdata = "48 89 5C 24 ?? 57 48 83 EC ?? 49 63 F8 48 8B D9 44 8B C7 E8 ?? ?? ?? ?? 48 8B 4B ?? 4C 8B 84 F9 ?? ?? ?? ?? 4D 85 C0 74 ?? 4C 89 40 ?? 48 8B 5C 24 ?? 48 83 C4 ?? 5F C3";
                l_memberAOB newblock = "40 53 48 83 EC ?? 4C 63 CA 48 8B 51 ?? 4A 8D 1C CA 4C 8B 83 ?? ?? ?? ?? 4D 85 C0 75 ?? 48 81 C2 ?? ?? ?? ?? C6 44 24 ?? ?? E8 ?? ?? ?? ?? 4C";
                l_memberAOB luaM_newgco = "48 89 5C 24 ?? 48 89 6C 24 ?? 56 57 41 57 48 83 EC ?? 48 8B 79 ?? 48 8D 42 ?? 45 0F B6 F8 48 8B DA 48 8B F1 48 3D ?? ?? ?? ?? 0F 83 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 4C 0F BE 0C 02 45 84 C9 0F 88 ?? ?? ?? ?? 4C 89 74 24 ?? 4E 8D 34 CF 49";
                l_memberAOB luaU_freeudata = "48 89 5c 24 08 48 89 74 24 10 57 48 83 ec 30 0f b6 42 03 49 8b f0 48 8b da 48 8b f9 3c 80 73 1d 44 8b c8 48 8b 41 48 4e 8b 94 c8 60 0d 00 00 4d 85 d2 74 1f 48 83 c2 10 41 ff d2 eb 16 75 14 48 63 42 04 48 8b 54 10 08 48 85 d2 74 06 48 8d 4b 10 ff d2";
                l_memberAOB lua_newthread = "48 89 5c 24 ?? 57 48 83 ec ?? 48 8b 51 ?? 48 8b d9 48 8b 42 ?? 48 39 42 ?? 72 ?? b2 ?? e8 ?? ?? ?? ?? f6 43 ?? ?? 74 ?? 4c 8d 43 ?? 48 8b d3 48 8b cb e8 ?? ?? ?? ?? 48 8b cb e8 ?? ?? ?? ?? 48 8b 4b ?? 48 8b f8 48 89 01 c7 41 ?? ?? ?? ?? ?? 48 83 43 ?? ??";
                l_memberAOB luaD_pcall = "48 89 5c 24 ?? 48 89 6c 24 ?? 48 89 74 24 ?? 4c 89 4c 24 ?? 57 41 54 41 55 41 56 41 57 48 83 ec ?? 4c 8b 71 ?? 48 8b f9 4c 2b 71 ?? 44 0f b7 61 ?? 44 0f b7 69 ?? 44 0f b6 79 ?? e8 ?? ?? ?? ?? 8b f0 85 c0 0f 84 ?? ?? ?? ?? 48 8b 5c 24 ?? 8b e8";
                l_memberAOB luau_execute = "40 55 48 81 ec ?? ?? ?? ?? 48 8b 41 ?? 48 8b e9 f6 40 ?? ?? 74 ?? 48 8b 40 ?? 48 8b 10 48 8b 41 ?? 48 8b 52 ?? 4c 8b 80 ?? ?? ?? ?? 41 ff d0 85 c0 0f 84 ?? ?? ?? ?? 48 89 9c 24 ?? ?? ?? ?? 48 89 b4 24 ?? ?? ?? ??";
                l_memberAOB lua_tolstringatom = "40 57 48 83 ec ?? 49 8b f8 4c 8b d1 85 d2 7e ?? 4c 8b 49 ?? 48 8d 05 ?? ?? ?? ?? 49 83 c1 ?? 48 63 d2 48 c1 e2 ?? 4c 03 ca 4c 3b 49 ?? 49 0f 42 c1 eb ?? 81 fa ?? ?? ?? ?? 7e ?? 48 63 c2 48 c1 e0 ?? 48 03 41 ?? eb ?? e8 ?? ?? ?? ?? 83 78 ?? ?? 74 ??";
                l_memberAOB coresumey = "48 89 5c 24 ?? 57 48 83 ec ?? ba ?? ?? ?? ?? 48 8b d9 e8 ?? ?? ?? ?? 48 8b f8 48 8b cb 48 85 c0 74 ?? 4c 8b 43 ?? 48 8b d0 4c 2b 43 ?? 49 c1 f8 ?? 41 ff c8 e8 ?? ?? ?? ?? 83 f8 ?? 75 ?? 48 8b 43 ?? 48 8b 90 ?? ??";
                l_memberAOB lab_vm_dispatch = "48 8b c4 48 89 58 ?? 55 56 57 41 54 41 55 41 56 41 57 48 81 ec ?? ?? ?? ?? 0f 29 70 ?? 4c 8d 25 ?? ?? ?? ?? 0f 29 78 ?? 48 8b e9 44 0f 29 40 ?? 0f 57 ff f3 44 0f 10 05 ?? ?? ?? ?? 44 0f 29 48 ?? f2 44 0f 10 0d ?? ?? ?? ?? 44 0f 29 90 ?? ?? ?? ?? f2 44 0f 10 15 ?? ?? ?? ?? 44 0f 29 98";
                l_memberAOB close_state = "48 89 5C 24 08 57 48 83 EC 20 48 8B 51 30 48 8B D9 48 8B 79 48 E8 ?? ?? ?? ?? 48 8B CB E8 ?? ?? ?? ?? 48 8B 53 48 45 33 C9 48 8B CB 4C 63 42 38";
                l_memberAOB luaF_freeproto = "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 30 44 0F B6 4A 02 49 8B F0 4C 63 82 98 00 00 00 48 8B DA 48 8B 52 10 48 8B F9 49 C1 E0 02 E8 ?? ?? ?? ?? 4C 63 83 ?? ?? ?? ??";
                l_memberAOB enumproto = "48 89 5C 24 10 48 89 74 24 18 57 41 56 41 57 48 81 EC ?? ?? ?? ?? 48 63 82 ?? ?? ?? ?? 48 8B DA 45 33 F6 48 8B F1 48 8D 14 40 48 63 83 ?? ?? ?? ?? 48 83 C0 0B 4C 8D 04 42 48 63 83 ?? ?? ?? ?? 4C 03 C0";
                l_memberAOB luaG_breakpoint = "48 89 5C 24 10 48 89 6C 24 18 48 89 74 24 20 57 41 56 41 57 48 83 EC ?? 4C 8B 52 ?? 33 F6 45 0F B6 F1 45 8B F8 48 8B DA 48 8B E9 4D 85 D2 0F 84 ?? ?? ?? ??";
                l_memberAOB luaM_freegco = "48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 57 48 83 ec 20 48 8b 59 48 49 8d 40 ff 41 0f b6 e9 49 8b f0 4c 8b da 48 8b f9 48 3d 00 04 00 00 0f 83 ?? ?? ?? ?? 48 8d 05 ?? ?? ?? ?? 45 0f b6 14 00 45 84 d2 0f 88 ?? ?? ?? ?? c6 02 00 48 8b 54 24 50 4c 8b 49 48 48 83 7a 28 00 75 28 83 7a 30 00 7d 22 49 0f be c2 49 8d 0c c1 48 8b 81 88 00 00 00 48 89 42 08 48 85 c0 74 03 48 89 10";

                //NOTE: this one is not a function! it's part of a standalone code block which also contains a call to gettypemapping.
                l_memberAOB stub_lvmload = "83 e0 ?? d3 e0 83 c1 ?? 44 0b c0 84 d2 78 ?? 45 85 c0 75 ?? 48 8b d5 eb ?? 49 8b 45 ?? 41 8d 48 ?? 48 8b 14 c8 0f b6 c3 ff c8 83 f8 ?? 73 ?? 48 8b 47 ?? 4c 8b 88 ?? ?? ?? ?? 4d 85 c9 74 ?? 44 8b 42 ?? 48 8b cf 48 83 c2 ?? 41 ff d1 0f b6 cb 88 44 0c ?? 42 0f b6 1c 36 48 ff c6 84";

                struct {
                    std::vector<std::pair<stringtableField, ptrdiff_t>> offsets {};
                    ptrdiff_t baseOffset = 0;
                } stringtableData;

                struct {
                    std::vector<std::pair<cbField, ptrdiff_t>> offsets {};
                    ptrdiff_t baseOffset = 0;
                    std::vector<std::pair<cbField, ptrdiff_t>> offsets_fromBase {};
                } cbData;

                struct {
                    std::vector<std::pair<ExecCallbacksField, ptrdiff_t>> offsets {};
                    ptrdiff_t baseOffset = 0;
                    std::vector<std::pair<ExecCallbacksField, ptrdiff_t>> offsets_fromBase {};
                } ecbData;

            public:
                explicit GlobalStateDumper(TValueDumper* tvd): tvDumper(tvd) {};
                std::string ToHeaderContents() override;
                void Scan() override;
        };
    }
}