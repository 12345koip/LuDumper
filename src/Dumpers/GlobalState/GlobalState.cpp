/*
This file was created by 12345koip for the
LuGo Structure Dumper, a subproject of the
LuGo executor.

See LICENSE and README for details.
*/

#include "GlobalState.hpp"

using namespace LuDumper::Dumpers;
using namespace LuDumper::Dissassembler;

void GlobalStateDumper::Scan() {
    puts("Dumping global state...");
    auto& Dissassembler = Dissassembler::Dissassembler::GetSingleton();

    const auto luaS_newlstr_signature = hat::parse_signature(luaS_newlstr).value();

    { //luaS_newlstr.
        puts("Scanning for luaS_newlstr...");

        //get luaS_newlstr disasm.
        auto luaS_newlstr_match = hat::find_pattern(luaS_newlstr_signature, ".text");
        if (!luaS_newlstr_match.has_result()) fail("luaS_newlstr");

        printf("luaS_newlstr @ %p\n", luaS_newlstr_match.get());

        //bounds of function
        uint8_t* start = reinterpret_cast<uint8_t*>(luaS_newlstr_match.get());
        uint8_t* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x80
        );
        
        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);


        for (const auto i: instructionList.GetAllInstructionsWhichMatch("mov", "* 8], ", true))
            debug_ins_log(i);
    }
}

std::string GlobalStateDumper::ToHeaderContents() {
    return "";
}