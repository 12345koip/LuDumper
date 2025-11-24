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

        };


        constexpr const char* TValueFieldToString(const TValueField field) {
            return "";
        };


        class TValueDumper: public BaseDumper<TValueField> {
            private:
                
        };
    }
}