/*
This file was created by 12345koip for the
LuGo Structure Dumper, a subproject of the
LuGo executor.

See LICENSE and README for details.
*/

#include "FileBits.hpp"
using namespace LuDumper;

std::string FileBits::GetStaticLuauStructs() {
    std::ostringstream buf {};

    //Value
    buf << "union Value {" << NEWLINE <<
        TAB_INDENT << "GCObject* gc;" << NEWLINE << TAB_INDENT << "void* p;" <<
        NEWLINE << TAB_INDENT << "double n;" << NEWLINE << TAB_INDENT << "int b;" <<
        NEWLINE << TAB_INDENT << "float v[2];" << TAB_INDENT << NEWLINE << "};";
    
    
    return buf.str();
}