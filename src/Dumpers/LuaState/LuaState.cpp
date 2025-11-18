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

        //all the matching instructions for moves into offsets in the Lua state.
        //A lot of offsets come just from these given the initialisation order.
        log_search("mov qword ptr [rdi + 0x??], rax");
        const auto allMoves = instructionList.GetAllInstructionsWhichMatch("mov", "qword ptr [rdi + 0x??], rax", false);

        /*
        From this, we should get 5 matches:
        1 - assignment of base_ci
        2 - assignment of ci
        3 - assignment of end_ci
        4 - assignment of stack
        5 - assignment of base
        */

        const LuaStateField fields[5] = {LuaStateField::base_ci, LuaStateField::ci, LuaStateField::end_ci, LuaStateField::stack, LuaStateField::base};
        for (int i = 0; i < 5; ++i) {
            auto& op = allMoves[i];
            auto offset = op->detail[0]->disp;
            log_offset(LuaStateFieldToString(fields[i]), offset);
            this->offsets.emplace(fields[i], offset);
        }

        //L->top is exposed by L->top++
        log_search("add qword ptr [rdi + 0x??], 0x10");

        const auto incrTopInsn = instructionList.GetInstructionWhichMatches("add", "qword ptr [rdi + 0x??], 0x10", false);
        auto offset_incrTop = incrTopInsn->detail[0]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::top), offset_incrTop);
        this->offsets.emplace(LuaStateField::top, offset_incrTop);

        //L->stacksize is exposed by the constant 0x2d, which is the expansion of BASIC_STACK_SIZE + EXTRA_STACK
        log_search("mov dword ptr [rdi + 0x??], 0x2d");
        const auto stackSzInstruction = instructionList.GetInstructionWhichMatches("mov", "dword ptr [rdi + 0x??], 0x2d", false);
        auto offset_stackSz = stackSzInstruction->detail[0]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::stacksize), offset_stackSz);
        this->offsets.emplace(LuaStateField::stacksize, offset_stackSz);

        //L->size_ci is exposed by the constant 8, which is the expansion of BASIC_CI_SIZE
        log_search("mov dword ptr [rdi + 0x??], 8");
        const auto bscCiSzIns = instructionList.GetInstructionWhichMatches("mov", "dword ptr [rdi + 0x??], 8", false);
        const auto ciSzOffset = bscCiSzIns->detail[0]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::size_ci), ciSzOffset);
        this->offsets.emplace(LuaStateField::size_ci, ciSzOffset);


        //stack_last is exposed by the single rcx mov
        log_search("mov qword ptr [rdi + 0x??], rcx");
        const auto stackLastInsn = instructionList.GetInstructionWhichMatches("mov", "qword ptr [rdi + 0x??], rcx", false);
        const auto stackLastOffset = stackLastInsn->detail[0]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::stack_last), stackLastOffset);
        this->offsets.emplace(LuaStateField::stack_last, stackLastOffset);

        //memcat is exposed by the first call to luaM_new_, it's in r8d.
        log_search("movzx r8d, byte ptr [rcx + 0x??]");
        const auto memcatInsn = instructionList.GetInstructionWhichMatches("movzx", "r8d, byte ptr [rcx + 0x??]", false);
        const auto memcatOffset = memcatInsn->detail[1]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::memcat), memcatOffset);
        this->offsets.emplace(LuaStateField::memcat, memcatOffset);
    }

    { //luaE_newthread
        puts("Scanning for luaE_newthread...");

        //get stack_init disasm.
        auto luaE_newthread_match = hat::find_pattern(luaE_newthread_signature, ".text");
        if (!luaE_newthread_match.has_result()) fail("luaE_newthread");

        printf("luaE_newthread @ %p\n", luaE_newthread_match.get());

        //function bounds
        uint8_t* start = reinterpret_cast<uint8_t*>(luaE_newthread_match.get());
        uint8_t* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x100
        );
        
        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        //L->tt is exposed when it is set to 9 (LUA_TTHREAD)
        log_search("mov byte ptr [rax], 9");
        const auto ttIns = instructionList.GetInstructionWhichMatches("mov", "byte ptr [rax], 9");
        const auto ttOffset = ttIns->detail[1]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::tt), ttOffset);
        this->offsets.emplace(LuaStateField::tt, ttOffset);

        //L->marked is exposed by currentwhite & 3
        log_search("and r8b, 3");
        const auto markedPos = instructionList.GetInstructionPosition("and", "r8b, 3", false) + 1;
        const auto markedOffset = markedPos->detail[0]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::marked), markedOffset);
        this->offsets.emplace(LuaStateField::marked, markedOffset);
    }
}

std::string LuaStateDumper::ToHeaderContents() const {
    return "";
}