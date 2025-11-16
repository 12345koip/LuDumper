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
        puts("Finding instruction: \"mov qword ptr [rdi + 0x??], rax\"");
        const auto allMoves = instructionList.GetAllInstructionsWhichMatch("mov", "qword ptr [rdi + 0x??], rax", false);

        /*
        From this, we should get 4 matches:
        1 - assignment of base_ci
        2 - assignment of end_ci
        3 - assignment of stack
        4 - assignment of base
        */

        puts("Dumping fields...");
        const LuaStateField fields[4] = {LuaStateField::base_ci, LuaStateField::end_ci, LuaStateField::stack, LuaStateField::base};
        for (int i = 0; i < 4; ++i) {
            auto& op = allMoves[i];
            auto offset = op->detail[0]->disp;
            log_offset(LuaStateFieldToString(fields[i]), offset);
            this->offsets.emplace(fields[i], offset);
        }

        //L->top is exposed by L->top++
        puts("Finding instruction: \"add qword ptr [rdi + 0x??], 0x10");

        const auto incrTopInsn = instructionList.GetInstructionWhichMatches("add", "qword ptr [rdi + 0x??], 0x10", false);
        auto offset_incrTop = incrTopInsn->detail[0]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::top), offset_incrTop);
        this->offsets.emplace(LuaStateField::top, offset_incrTop);

        
    }
}

std::string LuaStateDumper::ToHeaderContents() const {
    return "";
}