/*
This file was created by 12345koip for the
LuGo Structure Dumper, a subproject of the
LuGo executor.

See LICENSE and README for details.
*/

#include "LuaState.hpp"
using namespace LuDumper::Dumpers;
using namespace LuDumper::Dissassembler;

void LuaStateDumper::Scan() {
    puts("Dumping lua_State...");

    auto& Dissassembler = Dissassembler::Dissassembler::GetSingleton();

    //signatures.
    const auto stack_init_signature = hat::parse_signature(stack_init).value();
    const auto luaE_newthread_signature = hat::parse_signature(luaE_newthread).value();
    const auto lua_newthread_signature = hat::parse_signature(lua_newthread).value();
    const auto luaV_gettable_signature = hat::parse_signature(luaV_gettable).value();
    const auto luaD_call_signature = hat::parse_signature(luaD_call).value();
    const auto luaD_reallocstack_signature = hat::parse_signature(luaD_reallocstack).value();


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
            this->offsets.emplace_back(fields[i], offset);
        }

        //L->top is exposed by L->top++
        log_search("add qword ptr [rdi + 0x??], 0x10");

        const auto incrTopInsn = instructionList.GetInstructionWhichMatches("add", "qword ptr [rdi + 0x??], 0x10", false);
        auto offset_incrTop = incrTopInsn->detail[0]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::top), offset_incrTop);
        this->offsets.emplace_back(LuaStateField::top, offset_incrTop);

        //L->stacksize is exposed by the constant 0x2d, which is the expansion of BASIC_STACK_SIZE + EXTRA_STACK
        log_search("mov dword ptr [rdi + 0x??], 0x2d");
        const auto stackSzInstruction = instructionList.GetInstructionWhichMatches("mov", "dword ptr [rdi + 0x??], 0x2d", false);
        auto offset_stackSz = stackSzInstruction->detail[0]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::stacksize), offset_stackSz);
        this->offsets.emplace_back(LuaStateField::stacksize, offset_stackSz);

        //L->size_ci is exposed by the constant 8, which is the expansion of BASIC_CI_SIZE
        log_search("mov dword ptr [rdi + 0x??], 8");
        const auto bscCiSzIns = instructionList.GetInstructionWhichMatches("mov", "dword ptr [rdi + 0x??], 8", false);
        const auto ciSzOffset = bscCiSzIns->detail[0]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::size_ci), ciSzOffset);
        this->offsets.emplace_back(LuaStateField::size_ci, ciSzOffset);


        //stack_last is exposed by the single rcx mov
        log_search("mov qword ptr [rdi + 0x??], rcx");
        const auto stackLastInsn = instructionList.GetInstructionWhichMatches("mov", "qword ptr [rdi + 0x??], rcx", false);
        const auto stackLastOffset = stackLastInsn->detail[0]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::stack_last), stackLastOffset);
        this->offsets.emplace_back(LuaStateField::stack_last, stackLastOffset);

        //memcat is exposed by the first call to luaM_new_, it's in r8d.
        log_search("movzx r8d, byte ptr [rcx + 0x??]");
        const auto memcatInsn = instructionList.GetInstructionWhichMatches("movzx", "r8d, byte ptr [rcx + 0x??]", false);
        const auto memcatOffset = memcatInsn->detail[1]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::memcat), memcatOffset);
        this->offsets.emplace_back(LuaStateField::memcat, memcatOffset);
    }

    { //lua_newthread
        puts("Scanning for lua_newthread...");
        auto lua_newthread_match = hat::find_pattern(lua_newthread_signature, ".text");
        if (!lua_newthread_match.has_result()) fail("lua_newthread");

        printf("lua_newthread @ %p\n", lua_newthread_match.get());
        uint8_t* start = reinterpret_cast<uint8_t*>(lua_newthread_match.get());
        uint8_t* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x80
        );

        auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        //L->gclist is exposed in the call to luaC_barrierback. We can look backwards
        //from the second call to the first lea - this exposes the offset.
        log_search("call 0x??");
        const auto allCalls = instructionList.GetAllInstructionsWhichMatch("call", "", true);
        const auto& secondCall = allCalls[1];
        const auto secondCallPos = std::find(instructionList.begin(), instructionList.end(), secondCall);

        log_search("lea ..., [... + 0x??]");
        const AsmInstruction* lastLeaIns;
        for (int i = 0; i < 5; ++i) {
            auto ins = secondCallPos - i;

            if (ins->mnemonic == "lea") {
                //i have many regrets.
                lastLeaIns = &(*ins);
            }
        }

        const auto gclistOffset = lastLeaIns->detail[1]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::gclist), gclistOffset);
        this->offsets.emplace_back(LuaStateField::gclist, gclistOffset);
    }

    { //luaV_gettable
        puts("Scanning for luaV_gettable...");
        auto luaV_gettable_match = hat::find_pattern(luaV_gettable_signature, ".text");
        if (!luaV_gettable_match.has_result()) fail("luaV_gettable");

        printf("luaV_gettable @ %p\n", luaV_gettable_match.get());
        uint8_t* start = reinterpret_cast<uint8_t*>(luaV_gettable_match.get());
        uint8_t* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x80
        );

        auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        //L->cachedslot is exposed in the assignment L->cachedslot = gval2slot(h, res)
        //we'll go from the first call instruction (luaH_get) and walk forwards until
        //we find a matching mov.

        log_search("call 0x??");
        const auto call = instructionList.GetInstructionWhichMatches("call", "", true);
        const auto callPos = std::find(instructionList.begin(), instructionList.end(), call);
        log_search("mov dword ptr [... + 0x??], ...");

        const AsmInstruction* cachedslotMov;
        for (int i = 0; i < 10; ++i) {
            auto ins = callPos + i;

            if (ins->id == X86_INS_MOV && ins->operands.find("dword ptr [") != std::string::npos) {
                cachedslotMov = &(*ins);
                break;
            }
        }
        
        const auto cachedslotOffset = cachedslotMov->detail[0]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::cachedslot), cachedslotOffset);
        this->offsets.emplace_back(LuaStateField::cachedslot, cachedslotOffset);
    }


    { //luaD_call
        puts("Scanning for luaD_call...");

        //get luaD_call disasm.
        auto luaD_call_match = hat::find_pattern(luaD_call_signature, ".text");
        if (!luaD_call_match.has_result()) fail("luaD_call");

        printf("luaD_call @ %p\n", luaD_call_match.get());

        //bounds of function
        uint8_t* start = reinterpret_cast<uint8_t*>(luaD_call_match.get());
        uint8_t* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x195
        );
        
        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);



        //L->nCcalls is exposed when it is accessed at the start of the function for
        //whether or not to call luaD_checkCstack. It's the first movzx.
        log_search("movzx ..., word ptr [rcx + 0x??]");
        const auto first_movzx = instructionList.GetInstructionWhichMatches("movzx", "word ptr [rcx +", true);
        const auto nCcalls_offset = first_movzx->detail[1]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::nCcalls), nCcalls_offset);
        this->offsets.emplace_back(LuaStateField::nCcalls, nCcalls_offset);


        //L->baseCcalls is exposed when it is incremented in a C closure block.
        log_search("inc word ptr [?? + 0x??]");
        const auto inc_baseCcalls = instructionList.GetInstructionWhichMatches("inc", "word ptr [", true);
        const auto baseCcalls_offset = inc_baseCcalls->detail[0]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::baseCcalls), baseCcalls_offset);
        this->offsets.emplace_back(LuaStateField::baseCcalls, baseCcalls_offset);

        //L->status is exposed when it is read before comparison against LUA_YIELD and LUA_BREAK.
        //L->isactive is exposed when it is stored before new active flag is set.
        //both use movzx byte ptr.
        log_search("movzx byte ptr [... + 0x??]");
        const auto all_movzx_byte_ptr = instructionList.GetAllInstructionsWhichMatch("movzx", "byte ptr [", true);
        
        const AsmInstruction* isactiveIns = all_movzx_byte_ptr[0];
        const auto isactiveOffset = isactiveIns->detail[1]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::isactive), isactiveOffset);
        this->offsets.emplace_back(LuaStateField::isactive, isactiveOffset);

        const AsmInstruction* statusIns = all_movzx_byte_ptr[1];
        const auto statusOffset = statusIns->detail[1]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::status), statusOffset);
        this->offsets.emplace_back(LuaStateField::status, statusOffset);
    }

    { //luaD_reallocstack
        puts("Scanning for luaD_reallocstack...");

        //get luaD_reallocstack disasm.
        auto luaD_reallocstack_match = hat::find_pattern(luaD_reallocstack_signature, ".text");
        if (!luaD_reallocstack_match.has_result()) fail("luaD_reallocstack");

        printf("luaD_reallocstack @ %p\n", luaD_reallocstack_match.get());

        //bounds of function
        uint8_t* start = reinterpret_cast<uint8_t*>(luaD_reallocstack_match.get());
        uint8_t* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x195
        );
        
        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);


        //openupval is the second field which is read when L is in rcx.
        log_search("mov ..., qword ptr [rcx + 0x??]");
        const auto all_mov_qp_rcx = instructionList.GetAllInstructionsWhichMatch("mov", "qword ptr [rcx +", true);
        const auto openupval_offset = all_mov_qp_rcx[1]->detail[1]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::openupval), openupval_offset);
        this->offsets.emplace_back(LuaStateField::openupval, openupval_offset);

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
            reinterpret_cast<uintptr_t>(start) + 0x110
        );
        
        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        //L->tt is exposed when it is set to 9 (LUA_TTHREAD)
        log_search("mov byte ptr [rax], 9");
        const auto ttIns = instructionList.GetInstructionWhichMatches("mov", "byte ptr [rax], 9");
        const auto ttOffset = ttIns->detail[1]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::tt), ttOffset);
        this->offsets.emplace_back(LuaStateField::tt, ttOffset);

        //L->marked is exposed by currentwhite & 3
        log_search("and r8b, 3");
        const auto markedPos = instructionList.GetInstructionPosition("and", "r8b, 3", false) + 1;
        const auto markedOffset = markedPos->detail[0]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::marked), markedOffset);
        this->offsets.emplace_back(LuaStateField::marked, markedOffset);

        //L->global is exposed by the copy insn
        log_search("mov qword ptr [rax + 0x??], rcx");
        const auto gcpyInsn = instructionList.GetInstructionWhichMatches("mov", "qword ptr [rax + 0x??], rcx");
        const auto gOffset = gcpyInsn->detail[0]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::global), gOffset);
        this->offsets.emplace_back(LuaStateField::global, gOffset);

        //activememcat is exposed when it is copied from the main thread, as is gt.

        //singlestep is exposed by a similar one.
        log_search("mov byte ptr [rbx + 0x??], al");
        const auto allMovByteAl = instructionList.GetAllInstructionsWhichMatch("mov", "byte ptr [rbx + 0x??], al");
        const LuaStateField byteAlFields[2] = {LuaStateField::activememcat, LuaStateField::singlestep};

        for (int i = 0; i < allMovByteAl.size(); ++i) {
            auto field = byteAlFields[i];
            auto& ins = allMovByteAl[i];
            auto rOffset = ins->detail[0]->disp;
            log_offset(LuaStateFieldToString(field), rOffset);
            this->offsets.emplace_back(field, rOffset);
        }

        log_search("mov qword ptr [rbx + 0x??], rax");
        const auto allMovQRbx = instructionList.GetAllInstructionsWhichMatch("mov", "qword ptr [rbx + 0x??], rax");
        const auto gtCpyIns = *(allMovQRbx.end() - 1);
        const auto gtOffset = gtCpyIns->detail[0]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::gt), gtOffset);
        this->offsets.emplace_back(LuaStateField::gt, gtOffset);





        //there's now only two fields left: userdata and namecall.
        //we'll walk all the instructions which mov into L in the
        //inlined preinit_state and see which we don't have.
        std::array<const AsmInstruction*, 2> remaining = {nullptr, nullptr};

        for (const auto& i: allMovQRbx) {
            auto existing = std::find_if(this->offsets.begin(), this->offsets.end(), [&](const std::pair<LuaStateField, ptrdiff_t>& pair) -> bool {
                return pair.second == i->detail[0]->disp;
            });

            if (existing == this->offsets.end())
                remaining[remaining[0] == nullptr? 0: 1] = &(*i);
        }

        LUDUMP_ASSERT(remaining[0] == nullptr, "namecall retrieval failed");
        LUDUMP_ASSERT(remaining[1] == nullptr, "userdata retrieval failed");

        const auto* namecallIns = remaining[0];
        const auto namecallOffset = namecallIns->detail[0]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::namecall), namecallOffset);
        this->offsets.emplace_back(LuaStateField::namecall, namecallOffset);

        const auto* userdataIns = remaining[1];
        const auto userdataOffset = userdataIns->detail[0]->disp;
        log_offset(LuaStateFieldToString(LuaStateField::userdata), userdataOffset);
        this->offsets.emplace_back(LuaStateField::userdata, userdataOffset);
    }
}

std::string LuaStateDumper::ToHeaderContents() {
    //type string map. this just contains the string type of each field.
    static const std::unordered_map<LuaStateField, const char*> typesMap = {
        {LuaStateField::tt, "uint8_t"},
        {LuaStateField::marked, "uint8_t"},
        {LuaStateField::memcat, "uint8_t"},
        {LuaStateField::status, "uint8_t"},
        {LuaStateField::activememcat, "uint8_t"},
        {LuaStateField::isactive, "bool"},
        {LuaStateField::singlestep, "bool"},
        {LuaStateField::top, "StkId"},
        {LuaStateField::base, "StkId"},
        {LuaStateField::global, "global_State*"},
        {LuaStateField::ci, "CallInfo*"},
        {LuaStateField::stack_last, "StkId"},
        {LuaStateField::stack, "StkId"},
        {LuaStateField::end_ci, "CallInfo*"},
        {LuaStateField::base_ci, "CallInfo*"},
        {LuaStateField::stacksize, "int"},
        {LuaStateField::size_ci, "int"},
        {LuaStateField::nCcalls, "unsigned short"},
        {LuaStateField::baseCcalls, "unsigned short"},
        {LuaStateField::cachedslot, "int"},
        {LuaStateField::gt, "LuaTable*"},
        {LuaStateField::openupval, "UpVal*"},
        {LuaStateField::gclist, "GCObject*"},
        {LuaStateField::namecall, "TString*"},
        {LuaStateField::userdata, "void*"}
    };

    //sort the entries first.
    std::sort(this->offsets.begin(), this->offsets.end(), [](const auto& a, const auto& b) -> bool {
        return a.second < b.second;
    });

    //init buffer.
    std::ostringstream buf {};
    buf << "struct lua_State {\n";

    //each field will be added indented with the correct type
    for (const auto& [key, offset]: this->offsets) {
        buf << TAB_INDENT << typesMap.at(key) << " " << LuaStateFieldToString(key) << ";" <<
        "  //+0x" << std::hex << offset << NEWLINE;
    }

    //footer.
    buf << "};";



    return buf.str();
}