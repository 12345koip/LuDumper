/*
This file was created by 12345koip for the
LuGo Structure Dumper, a subproject of the
LuGo executor.

See LICENSE and README for details.
*/

#include "LuaState.hpp"
using namespace LuDumper::Dumpers;

void LuaStateDumper::Scan() {
    puts("Dumping Lua state...");

    auto& Dissassembler = Dissassembler::Dissassembler::GetSingleton();

    //signatures.
    const auto stack_init_signature = hat::parse_signature(stack_init).value();
    const auto luaE_newthread_signature = hat::parse_signature(luaE_newthread).value();


    { //stack_init
        puts("Scanning for stack_init...");

        //get stack_init disasm.
        auto stack_init_match = hat::find_pattern(stack_init_signature, ".text");
        if (!stack_init_match.has_result()) fail("stack_init");

        printf("stack_init @ %p\n", stack_init_match.get());

        //bounds of function
        uint8_t* start = reinterpret_cast<uint8_t*>(stack_init_match.get());
        uint8_t* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x200
        );
        
        const auto instructionList = *Dissassembler.Dissassemble(start, end, true); 

        auto firstCall = instructionList.GetInstructionPosition("call", "", true);

        //all the matching instructions for moves into offsets in the Lua state.
        //A lot of offsets come just from these given the initialisation order.
        const auto allMoves = instructionList.GetAllInstructionsWhichMatch("mov", "qword ptr [rdi + 0x??], rax", false);

        /*
        From this, we should get 4 matches:
        1 - assignment of base_ci
        2 - assignment of end_ci
        3 - assignment of stack
        4 - assignment of base
        */
        
        auto& base_ci_op = allMoves[0];
        auto base_ci_offset = base_ci_op->detail[0]->disp;
        log_offset("base_ci", base_ci_offset);
        this->offsets.emplace(LuaStateField::base_ci, base_ci_offset);
    }
}

std::string LuaStateDumper::ToHeaderContents() const {
    return "";
}