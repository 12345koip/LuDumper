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
                l_memberAOB luaS_newlstr = "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 48 83 EC ?? 48 8B F2 48 8B E9 48 8B CE 49 8B D0 49 8B F8 E8 ?? ?? ?? ?? 4C 8B 75 ?? 4C 63 C8 44 8B F8 4D 63 56 ?? 49 8B ?? 49 FF CA 4D 23";
                
            public:
                std::string ToHeaderContents() override;
                void Scan() override;
        };
    }
}