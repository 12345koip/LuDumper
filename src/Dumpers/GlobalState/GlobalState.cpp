/*
This file was created by 12345koip for the
LuGo Structure Dumper, a subproject of the
LuGo executor.

See LICENSE and README for details.
*/

#include "GlobalState.hpp"
#include <set>

using namespace LuDumper::Dumpers;
using namespace LuDumper::Dissassembler;

void GlobalStateDumper::Scan() {
    puts("Dumping global state...");
    auto& Dissassembler = Dissassembler::Dissassembler::GetSingleton();

    const auto luaS_newlstr_signature = hat::parse_signature(luaS_newlstr).value();
    const auto luaC_step_signature = hat::parse_signature(luaC_step).value();
    const auto luaC_fullGC_signature = hat::parse_signature(luaC_fullGC).value();
    const auto luaM_new_signature = hat::parse_signature(luaM_new).value();
    const auto freeblock_signature = hat::parse_signature(freeblock).value();
    const auto luaT_objtypename_signature = hat::parse_signature(luaT_objtypename).value();
    const auto pseudo2addr_signature = hat::parse_signature(pseudo2addr).value();
    const auto math_random_signature = hat::parse_signature(math_random).value();
    const auto lua_encodepointer_signature = hat::parse_signature(lua_encodepointer).value();
    const auto newUserdata_signature = hat::parse_signature(newUserdata).value();
    const auto newblock_signature = hat::parse_signature(newblock).value();
    const auto luaM_newgco_signature = hat::parse_signature(luaM_new).value();
    const auto luaU_freeudata_signature = hat::parse_signature(luaU_freeudata).value();
    const auto lua_newthread_signature = hat::parse_signature(lua_newthread).value();
    const auto luaD_pcall_signature = hat::parse_signature(luaD_pcall).value();
    const auto luau_execute_signature = hat::parse_signature(luau_execute).value();
    const auto lua_tolstringatom_signature = hat::parse_signature(lua_tolstringatom).value();
    const auto coresumey_signature = hat::parse_signature(coresumey).value();
    const auto lab_vm_dispatch_signature = hat::parse_signature(lab_vm_dispatch).value();
    const auto close_state_signature = hat::parse_signature(close_state).value();
    const auto luaF_freeproto_signature = hat::parse_signature(luaF_freeproto).value();
    const auto enumproto_signature = hat::parse_signature(enumproto).value();
    const auto stub_lvmload_signature = hat::parse_signature(stub_lvmload).value();
    const auto luaG_breakpoint_signature = hat::parse_signature(luaG_breakpoint).value();
    const auto luaM_freegco_signature = hat::parse_signature(luaM_freegco).value();

    //there's also sub-dumping and stuff through here like for cb and ecb
    //ok ty

    { //luaS_newlstr.
        puts("Scanning for luaS_newlstr...");

        //get luaS_newlstr disasm.
        auto luaS_newlstr_match = hat::find_pattern(luaS_newlstr_signature, ".text");
        if (!luaS_newlstr_match.has_result()) fail("luaS_newlstr");

        printf("luaS_newlstr @ %p\n", luaS_newlstr_match.get());

        //bounds of function
        uint8_t* start = reinterpret_cast<uint8_t*>(luaS_newlstr_match.get());
        uint8_t* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x170
        );
        
        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        { //stringtable fields.
            log_search("mov ..., qword ptr [... + 0x??]");
            const AsmInstruction* globalIns = instructionList.GetInstructionWhichMatches("mov", ", qword ptr [", true);
            const auto globalReg = globalIns->detail[0]->reg;


            const AsmInstruction* tb_hashIns = nullptr;
            const AsmInstruction* tb_sizeIns = nullptr;

            //for any and all dereferences involving this register:
            //- next one will be tb->size...
            //- ...followed by tb->hash
            log_search("movsxd ..., [... + 0x??]");
            log_search("mov ..., [... + 0x??]");
            for (auto it = instructionList.GetInstructionPosition(*globalIns); it != instructionList.end() && (!tb_hashIns || !tb_sizeIns); ++it) {
                if (it->detail[1]->base == globalReg && it->id == X86_INS_MOVSXD && !tb_sizeIns)
                    tb_sizeIns = &(*it);
                else if (it->detail[1]->base == globalReg && it->id == X86_INS_MOV)
                    tb_hashIns = &(*it);
            }

            LUDUMP_ASSERT(tb_hashIns != nullptr, "could not get hash ins");
            LUDUMP_ASSERT(tb_sizeIns != nullptr, "could not get size ins");

            const auto hashOffset_fromBase = tb_hashIns->detail[1]->disp;
            const auto sizeOffset_fromBase = tb_sizeIns->detail[1]->disp;

            //nuse.
            log_search("cmp dword ptr [... + 0x??], ...");
            const auto tb_nuseIns = instructionList.GetInstructionWhichMatches("cmp", "dword ptr [", true);
            const auto nuseOffset_fromBase = tb_nuseIns->detail[0]->disp;

            puts("Calculating stringtable base...");
            //now we have all the fields we can find the base and figure out what goes where
            const std::array<ptrdiff_t, 3> offsets = {sizeOffset_fromBase, nuseOffset_fromBase, hashOffset_fromBase};
            const auto& baseOffset = *std::min_element(offsets.begin(), offsets.end());
            log_offset("stringtable", baseOffset);
            const std::array<stringtableField, 3> fields = {stringtableField::size, stringtableField::nuse, stringtableField::hash};

            for (int i = 0; i < 3; ++i) {
                const auto field = fields[i];
                const auto offset = offsets[i] - baseOffset;

                log_offset(StringTableFieldToString(field), offset);
                this->stringtableData.offsets.emplace_back(field, offset);
            }

            this->stringtableData.baseOffset = baseOffset;
            this->offsets.emplace_back(GlobalStateField::strt, baseOffset);
        }


        //first movzx into rdx with byte ptr is currentwhite.
        log_search("movzx .dx, byte ptr [rcx + 0x??]");
        const AsmInstruction* currentwhiteIns = instructionList.GetInstructionWhichMatches("movzx", "dx, byte ptr [", true);
        const auto currentwhiteOffset = currentwhiteIns->detail[1]->disp;
        log_offset(GlobalStateFieldToString(GlobalStateField::currentwhite), currentwhiteOffset);
        this->offsets.emplace_back(GlobalStateField::currentwhite, currentwhiteOffset);
    }


    { //luaC_step.
        puts("Scanning for luaC_step...");

        //get luaC_step disasm.
        auto luaC_step_match = hat::find_pattern(luaC_step_signature, ".text");
        if (!luaC_step_match.has_result()) fail("luaC_step");

        printf("luaC_step @ %p\n", luaC_step_match.get());

        //bounds of function
        uint8_t* start = reinterpret_cast<uint8_t*>(luaC_step_match.get());
        uint8_t* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x250
        );
        
        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);






        //first two dword ptr operations use gcstepsize and gcstepmul.
        log_search("mov ..., dword ptr [... + 0x??]");
        const auto stepsizeIns = instructionList.GetInstructionWhichMatches("mov", ", dword ptr [", true);
        const auto stepsizeOffset = stepsizeIns->detail[1]->disp;
        log_offset(GlobalStateFieldToString(GlobalStateField::gcstepsize), stepsizeOffset);
        this->offsets.emplace_back(GlobalStateField::gcstepsize, stepsizeOffset);

        log_search("imul ..., dword ptr [... + 0x??]");
        const auto stepmulIns = instructionList.GetInstructionWhichMatches("imul", ", dword ptr [", true);
        const auto stepmulOffset = stepmulIns->detail[1]->disp;
        log_offset(GlobalStateFieldToString(GlobalStateField::gcstepmul), stepmulOffset);
        this->offsets.emplace_back(GlobalStateField::gcstepmul, stepmulOffset);


        //first mov ..., qword ptr is loading g from L, second is totalbytes and the following sub is GCthreshold
        log_search("mov ..., qword ptr [... + 0x??]");
        const auto allMovQword = instructionList.GetAllInstructionsWhichMatch("mov", ", qword ptr [", true);

        const auto totalbytesIns = allMovQword[1];
        const auto totalbytesOffset = totalbytesIns->detail[1]->disp;
        log_offset(GlobalStateFieldToString(GlobalStateField::totalbytes), totalbytesOffset);
        this->offsets.emplace_back(GlobalStateField::totalbytes, totalbytesOffset);

        const auto gcthresholdIns = instructionList.GetInstructionWhichMatches("sub", ", qword ptr [", true);
        const auto gcthresholdOffset = gcthresholdIns->detail[1]->disp;
        log_offset(GlobalStateFieldToString(GlobalStateField::GCthreshold), gcthresholdOffset);
        this->offsets.emplace_back(GlobalStateField::GCthreshold, gcthresholdOffset);


        //second movsxd with dword ptr is gcgoal.
        log_search("movsxd ..., dword ptr [... + 0x??]");
        const auto gcgoalIns = instructionList.GetAllInstructionsWhichMatch("movsxd", ", dword ptr [", true)[1];
        const auto gcgoalOffset = gcgoalIns->detail[1]->disp;
        log_offset(GlobalStateFieldToString(GlobalStateField::gcgoal), gcgoalOffset);
        this->offsets.emplace_back(GlobalStateField::gcgoal, gcgoalOffset);
    }

    { //luaC_fullGC.
        puts("Scanning for luaC_fullGC...");

        //get luaC_fullGC disasm.
        auto luaC_fullGC_match = hat::find_pattern(luaC_fullGC_signature, ".text");
        if (!luaC_fullGC_match.has_result()) fail("luaC_fullGC");

        printf("luaC_fullGC @ %p\n", luaC_fullGC_match.get());

        //bounds of function
        uint8_t* start = reinterpret_cast<uint8_t*>(luaC_fullGC_match.get());
        uint8_t* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x250
        );
        
        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);



        //first mov of 0x4 is byte ptr.
        log_search("mov byte ptr [... + 0x??], 4");
        const auto gcstateIns = instructionList.GetInstructionWhichMatches("mov", "], 4", true);
        const auto gcstateOffset = gcstateIns->detail[0]->disp;
        log_offset(GlobalStateFieldToString(GlobalStateField::gcstate), gcstateOffset);
        this->offsets.emplace_back(GlobalStateField::gcstate, gcstateOffset);

        
        
        //multiple exposed by mov qword ptr.
        log_search("mov qword ptr [... + 0x??], ...");
        const auto allMovQwordPtr = instructionList.GetAllInstructionsWhichMatch("mov", "qword ptr [", true);
        const GlobalStateField fields[6] = {GlobalStateField::sweepgcopage, GlobalStateField::allgcopages, GlobalStateField::gray, GlobalStateField::grayagain, GlobalStateField::weak, GlobalStateField::uvhead};

        for (int i = 0; i < 6; ++i) {
            const auto field = fields[i];
            const auto instruction = allMovQwordPtr[4 + i]; //4 is where the first one we want is.
            const auto offset = instruction->detail[i == 0 || i == 5? 1: 0]->disp;

            log_offset(GlobalStateFieldToString(field), offset);
            this->offsets.emplace_back(field, offset);
        }

        //index 12 is the one for mainthread.
        const auto mainthreadOffset = allMovQwordPtr[12]->detail[1]->disp;
        log_offset(GlobalStateFieldToString(GlobalStateField::mainthread), mainthreadOffset);
        this->offsets.emplace_back(GlobalStateField::mainthread, mainthreadOffset);


        //registryfree is exposed by comparison
        log_search("cmp dword ptr [... + 0x??], 5");
        const auto registryfreeIns = instructionList.GetInstructionWhichMatches("cmp", "], 5", true);
        const auto registryfreeOffset = registryfreeIns->detail[0]->disp;
        log_offset(GlobalStateFieldToString(GlobalStateField::registryfree), registryfreeOffset);

        //...and the next mov following it is the registry.
        const auto registryfreeInsPos = instructionList.GetInstructionPosition(*registryfreeIns);
        const AsmInstruction* registryIns = nullptr;

        for (auto it = registryfreeInsPos; it != registryfreeInsPos + 10 && it != instructionList.end() && !registryIns; ++it) {
            if (it->id == X86_INS_MOV)
                registryIns = &(*it);
        }

        LUDUMP_ASSERT(registryIns != nullptr, "could not get registry instruction");

        const auto registryOffset = registryIns->detail[1]->disp;
        log_offset(GlobalStateFieldToString(GlobalStateField::registry), registryOffset);
        this->offsets.emplace_back(GlobalStateField::registry, registryOffset);
    }


    { //luaM_new
        puts("Scanning for luaM_new...");

        //get luaM_new disasm.
        auto luaM_new_match = hat::find_pattern(luaM_new_signature, ".text");
        if (!luaM_new_match.has_result()) fail("luaM_new");

        printf("luaM_new @ %p\n", luaM_new_match.get());

        //bounds of function
        uint8_t* start = reinterpret_cast<uint8_t*>(luaM_new_match.get());
        uint8_t* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x250
        );
        
        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);


        //ud is exposed when frealloc is called
        log_search("mov rcx, qword ptr [... + 0x??]");
        const auto udIns = instructionList.GetInstructionWhichMatches("mov", "rcx, qword ptr [", true);
        const auto udOffset = udIns->detail[1]->disp;
        log_offset(GlobalStateFieldToString(GlobalStateField::ud), udOffset);
        this->offsets.emplace_back(GlobalStateField::ud, udOffset);

        //we can find the next call then trace back from it for the mov into its register
        //to find the frealloc offset
        const auto udInsPos = instructionList.GetInstructionPosition(*udIns);
        const auto nextCallPos = std::find_if(udInsPos, instructionList.end(), [](auto& otherIns) -> bool {
            return otherIns.id == X86_INS_CALL;
        });

        LUDUMP_ASSERT(nextCallPos != instructionList.end(), "could not find next call instruction");
        const auto movIntoCalledReg_r = std::find_if(std::make_reverse_iterator(nextCallPos), instructionList.rend(), [&](const auto& otherIns) -> bool {
            return otherIns.id == X86_INS_MOV && otherIns.detail[0]->reg == nextCallPos->detail[0]->reg;
        });

        LUDUMP_ASSERT(movIntoCalledReg_r != instructionList.rend(), "could not find mov into called register");
        const auto movIntoCalledReg = movIntoCalledReg_r.base() - 1;
        const auto freallocOffset = movIntoCalledReg->detail[1]->disp;

        log_offset(GlobalStateFieldToString(GlobalStateField::frealloc), freallocOffset);
        this->offsets.emplace_back(GlobalStateField::frealloc, freallocOffset);


        //memcatbytes is exposed when it is added to.
        log_search("add qword ptr [... + ... * 8 + 0x??], ...");
        const auto memcatbytesIns = instructionList.GetInstructionWhichMatches("add", "*8", true);
        const auto memcatbytesOffset = memcatbytesIns->detail[0]->disp;
        log_offset(GlobalStateFieldToString(GlobalStateField::memcatbytes), memcatbytesOffset);
        this->offsets.emplace_back(GlobalStateField::memcatbytes, memcatbytesOffset);




        log_search("mob ..., qword ptr [... + 0x??]");
        const auto g_cb_onallocateIns = instructionList.GetAllInstructionsWhichMatch("mov", ", qword ptr [", true)[3];
        const auto g_cb_onallocateOffset_fromBase = g_cb_onallocateIns->detail[1]->disp;
        this->cbData.offsets_fromBase.emplace_back(cbField::onallocate, g_cb_onallocateOffset_fromBase);
    }

    { //luaT_objtypename.
        puts("Scanning for luaT_objtypename...");

        //get luaT_objtypename disasm.
        auto luaT_objtypename_match = hat::find_pattern(luaT_objtypename_signature, ".text");
        if (!luaT_objtypename_match.has_result()) fail("luaT_objtypename");

        printf("luaT_objtypename @ %p\n", luaT_objtypename_match.get());

        //bounds of function
        uint8_t* start = reinterpret_cast<uint8_t*>(luaT_objtypename_match.get());
        uint8_t* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x250
        );
        
        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);



        //multiple fields are exposed with mutliplaction by 8 in the mov.
        log_search("mov ..., [... *8 (+ ...)?], ...");
        const auto allMovWithMul = instructionList.GetAllInstructionsWhichMatch("mov", "*8", true);
        

        const GlobalStateField mulFields[3] = {GlobalStateField::lightuserdataname, GlobalStateField::mt, GlobalStateField::ttname};
        for (int i = 0; i < 3; ++i) {
            const GlobalStateField field = mulFields[i];
            const AsmInstruction* ins = allMovWithMul[i];

            const auto offset = ins->detail[1]->disp;
            log_offset(GlobalStateFieldToString(field), offset);
            this->offsets.emplace_back(field, offset);
        }

        //fourth one exposes tmname.
        log_search("mov ..., qword ptr [... + 0x??]");
        const auto tmnameIns = instructionList.GetAllInstructionsWhichMatch("mov", ", qword ptr [", true)[3];
        const auto tmnameOffset = tmnameIns->detail[1]->disp;
        log_offset(GlobalStateFieldToString(GlobalStateField::tmname), tmnameOffset);
        this->offsets.emplace_back(GlobalStateField::tmname, tmnameOffset);
    }

    { //pseudo2addr.
        puts("Scanning for pseudo2addr...");

        //get pseudo2addr disasm.
        auto pseudo2addr_match = hat::find_pattern(pseudo2addr_signature, ".text");
        if (!pseudo2addr_match.has_result()) fail("pseudo2addr");

        printf("pseudo2addr @ %p\n", pseudo2addr_match.get());

        //bounds of function
        auto* start = reinterpret_cast<uint8_t*>(pseudo2addr_match.get());
        auto* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x120
        );
        
        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        //we'll look at any of the writes of tt as LUA_TTABLE and subtract the offset of tt within tvalue from it.
        const auto ttSet = instructionList.GetInstructionWhichMatches("mov", "], 6", true);
        const auto rawttOffset = ttSet->detail[0]->disp;

        const auto pseudotempOffset = rawttOffset - this->tvDumper->GetOffset(TValueField::tt);
        log_offset(GlobalStateFieldToString(GlobalStateField::pseudotemp), pseudotempOffset);
        this->offsets.emplace_back(GlobalStateField::pseudotemp, pseudotempOffset);
    }

    { //math.random exposes rngstate
        puts("Scanning for math_random...");

        //get math_random disasm.
        auto math_random_match = hat::find_pattern(math_random_signature, ".text");
        if (!math_random_match.has_result()) fail("math_random");

        printf("math_random @ %p\n", math_random_match.get());

        //bounds of function
        uint8_t* start = reinterpret_cast<uint8_t*>(math_random_match.get());
        uint8_t* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x250
        );

        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        //the fourth mov qword ptr exposes rngstate.
        log_search("mov qword ptr [... + 0x??], ...");
        const auto rngstateIns = instructionList.GetAllInstructionsWhichMatch("mov", "qword ptr [", true)[3];
        const auto rngstateOffset = rngstateIns->detail[1]->disp;
        log_offset(GlobalStateFieldToString(GlobalStateField::rngstate), rngstateOffset);
        this->offsets.emplace_back(GlobalStateField::rngstate, rngstateOffset);
    }

    { //lua_encodepointer.
        puts("Scanning for lua_encodepointer...");

        //get lua_encodepointer disasm.
        auto lua_encodepointer_match = hat::find_pattern(lua_encodepointer_signature, ".text");
        if (!lua_encodepointer_match.has_result()) fail("lua_encodepointer");

        printf("lua_encodepointer @ %p\n", lua_encodepointer_match.get());

        //bounds of function
        uint8_t* start = reinterpret_cast<uint8_t*>(lua_encodepointer_match.get());
        uint8_t* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x250
        );

        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        //second imul instruction is base of ptrenckey
        log_search("imul ..., ...");
        const auto ptrenckeyIns = instructionList.GetAllInstructionsWhichMatch("imul", "", true)[1];
        const auto ptrenckeyOffset = ptrenckeyIns->detail[1]->disp;
        log_offset(GlobalStateFieldToString(GlobalStateField::ptrenckey), ptrenckeyOffset);
        this->offsets.emplace_back(GlobalStateField::ptrenckey, ptrenckeyOffset);
    }

    { //newUserdata.
        puts("Scanning for newUserdata...");

        //get newUserdata disasm.
        auto newUserdata_match = hat::find_pattern(newUserdata_signature, ".text");
        if (!newUserdata_match.has_result()) fail("newUserdata");

        printf("newUserdata @ %p\n", newUserdata_match.get());

        //bounds of function
        auto* start = reinterpret_cast<uint8_t*>(newUserdata_match.get());
        auto* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x250
        );

        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        log_search("mov ..., qword ptr [... + ...*8 + 0x??]");
        const auto udatamtIns = instructionList.GetInstructionWhichMatches("mov", "*8", true);
        const auto udatamtOffset = udatamtIns->detail[1]->disp;
        log_offset(GlobalStateFieldToString(GlobalStateField::udatamt), udatamtOffset);
        this->offsets.emplace_back(GlobalStateField::udatamt, udatamtOffset);
    }

    { //newblock
        puts("Scanning for newblock...");

        //get newblock disasm.
        auto newblock_match = hat::find_pattern(newblock_signature, ".text");
        if (!newblock_match.has_result()) fail("newblock");

        printf("newblock @ %p\n", newblock_match.get());

        //bounds of function
        auto* start = reinterpret_cast<uint8_t*>(newblock_match.get());
        auto* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x250
        );

        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        //first lea with *8 indexes g->freepages. we can look for the next mov using that register.
        log_search("lea ..., [... + ...*8 + ...]");
        const auto leaIns = instructionList.GetInstructionWhichMatches("lea", "*8", true);
        const auto leaInsPos = instructionList.GetInstructionPosition(*leaIns);

        const auto freepagesIns = std::ranges::find_if(leaInsPos, instructionList.end(), [](auto& ins) -> bool {
            return ins.id == X86_INS_MOV;
        });

        LUDUMP_ASSERT(freepagesIns != instructionList.end(), "failed to locate freepages instruction");

        const auto freepagesOffset = freepagesIns->detail[1]->disp;
        log_offset(GlobalStateFieldToString(GlobalStateField::freepages), freepagesOffset);
        this->offsets.emplace_back(GlobalStateField::freepages, freepagesOffset);

        //the first mov into r8 of a qword ptr exposes allpages.
        const auto allpagesIns = instructionList.GetInstructionWhichMatches("mov", "r8, qword ptr [", true);
        const auto allpagesOffset = allpagesIns->detail[1]->disp;
        log_offset(GlobalStateFieldToString(GlobalStateField::allpages), allpagesOffset);
        this->offsets.emplace_back(GlobalStateField::allpages, allpagesOffset);
    }

    { //luaM_newgco
        puts("Scanning for luaM_newgco...");

        //get luaM_newgco disasm.
        auto luaM_newgco_match = hat::find_pattern(luaM_newgco_signature, ".text");
        if (!luaM_newgco_match.has_result()) fail("luaM_newgco");

        printf("luaM_newgco @ %p\n", luaM_newgco_match.get());

        //bounds of function
        auto* start = reinterpret_cast<uint8_t*>(luaM_newgco_match.get());
        auto* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x250
        );

        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);


        //the second lea into rdx exposes allgcopages.
        log_search("lea rdx, ... + 0x??");
        const auto allgcopagesIns = instructionList.GetAllInstructionsWhichMatch("lea", "rdx, [", true)[1];
        const auto allgcopagesOffset = allgcopagesIns->detail[1]->disp;
        log_offset(GlobalStateFieldToString(GlobalStateField::allgcopages), allgcopagesOffset);
        this->offsets.emplace_back(GlobalStateField::allgcopages, allgcopagesOffset);
    }

    { //luaU_freeudata.
        puts("Scanning for luaU_freeudata...");

        //get luaU_freeudata disasm.
        auto luaU_freeudata_match = hat::find_pattern(luaU_freeudata_signature, ".text");
        if (!luaU_freeudata_match.has_result()) fail("luaU_freeudata");

        printf("luaU_freeudata @ %p\n", luaU_freeudata_match.get());

        //bounds of function
        auto* start = reinterpret_cast<uint8_t*>(luaU_freeudata_match.get());
        auto* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x250
        );

        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        //first mov qword ptr with a *8 is udatagc
        log_search("mov ..., qword ptr [... + ...*8 + 0x??]");
        const auto udatagcIns = instructionList.GetInstructionWhichMatches("mov", "*8", true);
        const auto udatagcOffset = udatagcIns->detail[1]->disp;
        log_offset(GlobalStateFieldToString(GlobalStateField::udatagc), udatagcOffset);
        this->offsets.emplace_back(GlobalStateField::udatagc, udatagcOffset);
    }

    { //lua_newthread
        puts("Scanning for lua_newthread...");

        //get lua_newthread disasm.
        auto lua_newthread_match = hat::find_pattern(lua_newthread_signature, ".text");
        if (!lua_newthread_match.has_result()) fail("lua_newthread");

        printf("lua_newthread @ %p\n", lua_newthread_match.get());

        //bounds of function
        auto* start = reinterpret_cast<uint8_t*>(lua_newthread_match.get());
        auto* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x250
        );

        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        log_search("mov ..., qword ptr [... + 0x??]");
        const auto userthreadIns = instructionList.GetAllInstructionsWhichMatch("mov", ", qword ptr [", true)[4];
        const auto userthreadOffset_fromBase = userthreadIns->detail[1]->disp;
        this->cbData.offsets_fromBase.emplace_back(cbField::userthread, userthreadOffset_fromBase);
    }

    { //luaD_pcall.
        puts("Scanning for luaD_pcall...");

        //get luaD_pcall disasm.
        auto luaD_pcall_match = hat::find_pattern(luaD_pcall_signature, ".text");
        if (!luaD_pcall_match.has_result()) fail("luaD_pcall");

        printf("luaD_pcall @ %p\n", luaD_pcall_match.get());

        //bounds of function
        auto* start = reinterpret_cast<uint8_t*>(luaD_pcall_match.get());
        auto* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x250
        );

        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        log_search("mov ..., qword ptr [... + 0x??]");
        const auto funcIns = instructionList.GetAllInstructionsWhichMatch("mov", ", qword ptr [", true)[5];
        const auto funcOffset_fromBase = funcIns->detail[1]->disp;
        this->cbData.offsets_fromBase.emplace_back(cbField::debugprotectederror, funcOffset_fromBase);
    }

    { //luau_execute.
        puts("Scanning for luau_execute...");

        //get luau_execute disasm.
        auto luau_execute_match = hat::find_pattern(luau_execute_signature, ".text");
        if (!luau_execute_match.has_result()) fail("luau_execute");

        printf("luau_execute @ %p\n", luau_execute_match.get());

        //bounds of function
        auto* start = reinterpret_cast<uint8_t*>(luau_execute_match.get());
        auto* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x250
        );

        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        //6th mov qword ptr is interrupt.
        log_search("mov ..., qword ptr [... + 0x??]");
        const auto interruptIns = instructionList.GetAllInstructionsWhichMatch("mov", ", qword ptr [", true)[5];
        const auto interruptOffset_fromBase = interruptIns->detail[1]->disp;
        this->cbData.offsets_fromBase.emplace_back(cbField::interrupt, interruptOffset_fromBase);
    }

    { //lua_tolstringatom.
        puts("Scanning for lua_tolstringatom...");

        //get lua_tolstringatom disasm.
        auto lua_tolstringatom_match = hat::find_pattern(lua_tolstringatom_signature, ".text");
        if (!lua_tolstringatom_match.has_result()) fail("lua_tolstringatom");

        printf("lua_tolstringatom @ %p\n", lua_tolstringatom_match.get());

        //bounds of function
        auto* start = reinterpret_cast<uint8_t*>(lua_tolstringatom_match.get());
        auto* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x250
        );

        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        log_search("mov ..., qword ptr [... + 0x??]");
        const auto useratomIns = instructionList.GetAllInstructionsWhichMatch("mov", ", qword ptr [", true)[3];
        const auto useratomOffset_fromBase = useratomIns->detail[1]->disp;
        this->cbData.offsets_fromBase.emplace_back(cbField::useratom, useratomOffset_fromBase);
    }

    { //coresumey is just one of the functions where interruptThread is inlined at.
        puts("Scanning for coresumey...");

        //get coresumey disasm.
        auto coresumey_match = hat::find_pattern(coresumey_signature, ".text");
        if (!coresumey_match.has_result()) fail("coresumey");

        printf("coresumey @ %p\n", coresumey_match.get());

        //bounds of function
        auto* start = reinterpret_cast<uint8_t*>(coresumey_match.get());
        auto* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x250
        );

        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);


        //fourth mov of qword ptr where the qword ptr is the second part of the operands
        //is debuginterrupt.
        log_search("mov ..., qword ptr [... + 0x??]");
        const auto debuginterruptIns = instructionList.GetAllInstructionsWhichMatch("mov", ", qword ptr [", true)[2];
        const auto debuginterruptOffset_fromBase = debuginterruptIns->detail[1]->disp;
        this->cbData.offsets_fromBase.emplace_back(cbField::debuginterrupt, debuginterruptOffset_fromBase);
    }

    { //dispatch label in the vm.
        puts("Scanning for lab_vm_dispatch...");

        //get lab_vm_dispatch disasm.
        auto lab_vm_dispatch_match = hat::find_pattern(lab_vm_dispatch_signature, ".text");
        if (!lab_vm_dispatch_match.has_result()) fail("lab_vm_dispatch");

        printf("lab_vm_dispatch @ %p\n", lab_vm_dispatch_match.get());

        //bounds of function
        auto* start = reinterpret_cast<uint8_t*>(lab_vm_dispatch_match.get());
        auto* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x250
        );

        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        //we'll look for the first call (which is to luau_callhook), and
        //then we'll walk backwards until we find a mov into rdx for debugstep.
        log_search("call ...");
        const auto firstCall = instructionList.GetInstructionWhichMatches("call", "", true);
        const auto firstCallPos = instructionList.GetInstructionPosition(*firstCall);

        log_search("mov rdx, qword ptr [... + 0x??];");
        const auto movIntoRdx = std::find_if(std::make_reverse_iterator(firstCallPos), instructionList.rend(), [](const auto& ins) -> bool {
            return ins.id == X86_INS_MOV && ins.detail[0]->reg == X86_REG_RDX;
        });

        LUDUMP_ASSERT(movIntoRdx != instructionList.rend(), "could not get last mov into rdx before call");
        const auto debugstepOffset = movIntoRdx->detail[1]->disp;
        this->cbData.offsets_fromBase.emplace_back(cbField::debugstep, debugstepOffset);
    }

    { //now we have gathered all the function fields of lua_Callbacks, we can calculate userdata and then the position of cb.
        //NOTE: lua_Callbacks size is only 0x80, not 0x88, bc panic will be stripped
        //bc roblox build of luau does not use longjmp error handling.

        std::sort(this->cbData.offsets_fromBase.begin(), this->cbData.offsets_fromBase.end(), [](const auto& a, const auto& b) -> bool {
            return a.second < b.second;
        });

        auto& knownOffsets = this->cbData.offsets_fromBase;

        //we must compare gaps between calculated offsets to see if another pointer could fit between.
        std::vector<ptrdiff_t> candidates {};
        for (ptrdiff_t i = 1; i < knownOffsets.size(); ++i) {
            ptrdiff_t gap = knownOffsets[i].second - knownOffsets[i - 1].second;

            if (gap > 0x8) {
                candidates.push_back(knownOffsets[i - 1].second + 0x8);
                break; //we only expect there to be one missing slot.
            }
        }

        //base offset or midpoint offset accordingly.
        const auto last = knownOffsets.back().second;
        if (candidates.empty() && 0x80 - last > 0x8)
            candidates.push_back(last + 0x8);
        else if (candidates.empty() && knownOffsets.front().second > 0)
            candidates.push_back(0);

        LUDUMP_ASSERT(candidates.size() <= 1, "offset calculation failed: multiple candidates remain");

        //we can now choose the correct offset.
        ptrdiff_t userdataOffset_fromBase = candidates.empty()? 0: candidates[0];
        puts("userdata offset from base identified.");

        //insert it.
        const auto insertPair = std::make_pair(cbField::userdata, userdataOffset_fromBase);
        const auto insertPos = std::ranges::lower_bound(knownOffsets.begin(), knownOffsets.end(), insertPair, [](const auto& a, const auto& b) -> bool {
            return a.second < b.second;
        });

        knownOffsets.insert(insertPos, insertPair);


        //we will now take the base of the struct and populate the standalone field.
        const auto frontOffset = knownOffsets.front().second;
        const auto cbBase = frontOffset != 0? frontOffset: knownOffsets[1].second;
        log_offset("cb", cbBase);
        this->cbData.baseOffset = cbBase;
        this->offsets.emplace_back(GlobalStateField::cb, cbBase);

        for (const auto& [key, offset]: knownOffsets) {
            const ptrdiff_t offset_fromStructBase = offset - cbBase;
            log_offset(cbFieldToString(key), offset_fromStructBase);
            this->cbData.offsets.emplace_back(key, offset_fromStructBase);
        }
    }




    //lua_ExecutionCallbacks bits.
    { //close_state.
        puts("Scanning for close_state...");

        //get close_state disasm.
        auto close_state_match = hat::find_pattern(close_state_signature, ".text");
        if (!close_state_match.has_result()) fail("close_state");

        printf("close_state @ %p\n", close_state_match.get());

        //bounds of function
        auto* start = reinterpret_cast<uint8_t*>(close_state_match.get());
        auto* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x95
        );

        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        //we will look at the call, observe the register used,
        //then walk back to the last mov into that register, which will give us close.
        log_search("call ...");
        const auto allCall = instructionList.GetAllInstructionsWhichMatch("call", "", true);
        const auto lastCall = allCall.back();

        const auto regUsed = lastCall->detail[0]->reg;
        const auto lastCallPos = instructionList.GetInstructionPosition(*lastCall);

        //we will find the first mov into that reg.
        const auto movIntoReg = std::find_if(std::make_reverse_iterator(lastCallPos), instructionList.rend(), [regUsed](const auto& ins) -> bool {
           return !ins.detail.empty() && ins.detail[0]->reg == regUsed && ins.id == X86_INS_MOV;
        });

        LUDUMP_ASSERT(movIntoReg != instructionList.rend(), "could not locate mov into register");
        const auto closeOffset = movIntoReg->detail[1]->disp;
        this->ecbData.offsets_fromBase.emplace_back(ExecCallbacksField::close, closeOffset);
    }

    { //luaF_freeproto
        puts("Scanning for luaF_freeproto...");

        //get luaF_freeproto disasm.
        auto luaF_freeproto_match = hat::find_pattern(luaF_freeproto_signature, ".text");
        if (!luaF_freeproto_match.has_result()) fail("luaF_freeproto");

        printf("luaF_freeproto @ %p\n", luaF_freeproto_match.get());

        //bounds of function
        auto* start = reinterpret_cast<uint8_t*>(luaF_freeproto_match.get());
        auto* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x150
        );

        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        //the first indirect call to a qword ptr will be destroy.
        log_search("call qword ptr [");
        const auto callQwordPtr = instructionList.GetInstructionWhichMatches("call", "qword ptr [", true);
        const auto destroyOffset = callQwordPtr->detail[0]->disp;
        this->ecbData.offsets_fromBase.emplace_back(ExecCallbacksField::destroy, destroyOffset);
    }

    { //enumproto.
        puts("Scanning for enumproto...");

        //get enumproto disasm.
        auto enumproto_match = hat::find_pattern(enumproto_signature, ".text");
        if (!enumproto_match.has_result()) fail("enumproto");

        printf("enumproto @ %p\n", enumproto_match.get());

        //bounds of function
        auto* start = reinterpret_cast<uint8_t*>(enumproto_match.get());
        auto* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x110
        );

        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        //mov with qword ptr exposes getmemorysize.
        log_search("mov ..., qword ptr [... + 0x??]");
        const auto getmemorysizeIns = instructionList.GetAllInstructionsWhichMatch("mov", ", qword ptr [", true)[2];
        const auto getmemorysizeOffset = getmemorysizeIns->detail[1]->disp;
        this->ecbData.offsets_fromBase.emplace_back(ExecCallbacksField::getmemorysize, getmemorysizeOffset);
    }

    { //lvmload stub.
        puts("Scanning for stub_lvmload...");

        //get stub_lvmload disasm.
        auto stub_lvmload_match = hat::find_pattern(stub_lvmload_signature, ".text");
        if (!stub_lvmload_match.has_result()) fail("stub_lvmload");

        printf("stub_lvmload @ %p\n", stub_lvmload_match.get());

        //bounds of function
        auto* start = reinterpret_cast<uint8_t*>(stub_lvmload_match.get());
        auto* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x110
        );

        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        //we will look for the first call to a register, then walk backwards for the first mov into that register.
        const auto callIntoReg = std::find_if(instructionList.begin(), instructionList.end(), [](const auto& ins) -> bool {
            return ins.detail.size() > 0 && ins.id == X86_INS_CALL && ins.detail[0]->reg != X86_REG_INVALID;
        });

        LUDUMP_ASSERT(callIntoReg != instructionList.end(), "could not locate reg call");
        const auto regUsed = callIntoReg->detail[0]->reg;

        const auto lastMovIntoReg = std::find_if(std::make_reverse_iterator(callIntoReg), instructionList.rend(), [regUsed](const auto& ins) -> bool {
            return ins.detail.size() > 0 && ins.detail[0]->reg == regUsed && ins.id == X86_INS_MOV;
        });

        LUDUMP_ASSERT(lastMovIntoReg != instructionList.rend(), "could not find mov into reg");

        const auto gettypemappingOffset = lastMovIntoReg->detail[1]->disp;
        this->ecbData.offsets_fromBase.emplace_back(ExecCallbacksField::gettypemapping, gettypemappingOffset);
    }

    { //luaG_breakpoint.
        puts("Scanning for luaG_breakpoint...");

        //get luaG_breakpoint disasm.
        auto luaG_breakpoint_match = hat::find_pattern(luaG_breakpoint_signature, ".text");
        if (!luaG_breakpoint_match.has_result()) fail("luaG_breakpoint");

        printf("luaG_breakpoint @ %p\n", luaG_breakpoint_match.get());

        //bounds of function
        auto* start = reinterpret_cast<uint8_t*>(luaG_breakpoint_match.get());
        auto* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x110
        );

        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        const auto disableIns = instructionList.GetAllInstructionsWhichMatch("mov", ", qword ptr [", true)[2];
        const auto disableOffset = disableIns->detail[1]->disp;
        this->ecbData.offsets_fromBase.emplace_back(ExecCallbacksField::disable, disableOffset);
    }

    { //calculate context ptr and sort, etc. NOTE: entry is omitted, it must have been stripped at compile time.
        std::sort(this->ecbData.offsets_fromBase.begin(), this->ecbData.offsets_fromBase.end(), [](const auto& a, const auto& b) -> bool {
            return a.second < b.second;
        });

        auto& knownOffsets = this->ecbData.offsets_fromBase;

        //we must compare gaps between calculated offsets to see if another pointer could fit between.
        std::vector<ptrdiff_t> candidates {};
        for (ptrdiff_t i = 1; i < knownOffsets.size(); ++i) {
            ptrdiff_t gap = knownOffsets[i].second - knownOffsets[i - 1].second;

            if (gap > 0x8) {
                candidates.push_back(knownOffsets[i - 1].second + 0x8);
                break; //we only expect there to be one missing slot.
            }
        }

        //base offset or midpoint offset accordingly.
        const auto last = knownOffsets.back().second;
        if (candidates.empty() && 0x48 - last > 0x8)
            candidates.push_back(last + 0x8);
        else if (candidates.empty() && knownOffsets.front().second > 0)
            candidates.push_back(0);

        LUDUMP_ASSERT(candidates.size() <= 1, "offset calculation failed: multiple candidates remain");

        //we can now choose the correct offset.
        ptrdiff_t contextOffset_fromBase = candidates.empty()? 0: candidates[0];
        puts("context offset from base identified.");

        //insert it.
        const auto insertPair = std::make_pair(ExecCallbacksField::context, contextOffset_fromBase);
        const auto insertPos = std::ranges::lower_bound(knownOffsets.begin(), knownOffsets.end(), insertPair, [](const auto& a, const auto& b) -> bool {
            return a.second < b.second;
        });

        knownOffsets.insert(insertPos, insertPair);


        //we will now take the base of the struct and populate the standalone field.
        const auto frontOffset = knownOffsets.front().second;
        const auto ecbBase = frontOffset != 0? frontOffset: knownOffsets[1].second;
        log_offset("ecb", ecbBase);
        this->ecbData.baseOffset = ecbBase;
        this->offsets.emplace_back(GlobalStateField::ecb, ecbBase);

        for (const auto& [key, offset]: knownOffsets) {
            const ptrdiff_t offset_fromStructBase = offset - ecbBase;
            log_offset(ExecCallbacksFieldToString(key), offset_fromStructBase);
            this->ecbData.offsets.emplace_back(key, offset_fromStructBase);
        }
    }

    {
        //luaM_freegco_
        puts("Scanning for luaM_freegco_...");

        //get luaM_freegco_ disasm.
        auto luaM_freegco__match = hat::find_pattern(luaM_freegco_signature, ".text");
        if (!luaM_freegco__match.has_result()) fail("luaM_freegco_");

        printf("luaM_freegco_ @ %p\n", luaM_freegco__match.get());

        //bounds of function
        auto* start = reinterpret_cast<uint8_t*>(luaM_freegco__match.get());
        auto* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x110
        );

        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        log_search("mov ..., qword ptr [... + 0x??]");
        const AsmInstruction* freegcopagesIns = instructionList.GetAllInstructionsWhichMatch("mov", ", qword ptr [", true)[3];
        const auto freegcopagesOffset = freegcopagesIns->detail[1]->disp;
        log_offset(GlobalStateFieldToString(GlobalStateField::freegcopages), freegcopagesOffset);
        this->offsets.emplace_back(GlobalStateField::freegcopages, freegcopagesOffset);
    }
}

std::string GlobalStateDumper::ToHeaderContents() {
    std::ranges::sort(this->offsets.begin(), this->offsets.end(), [](auto& a, auto& b) -> bool {
        return a.second < b.second;
    });

    std::ostringstream buf {};

    { //stringtable
        std::ostringstream strtBuf {};
        strtBuf << "struct stringtable {" << NEWLINE;

        std::ranges::sort(this->stringtableData.offsets.begin(), this->stringtableData.offsets.end(), [](auto& a, auto& b) -> bool {
            return a.second < b.second;
        });

        const std::unordered_map<stringtableField, const char*> strtTypesMap = {
            {stringtableField::hash, "TString**"},
            {stringtableField::nuse, "uint32_t"},
            {stringtableField::size, "int"}
        };

        for (const auto& [key, offset]: this->stringtableData.offsets)
            strtBuf << TAB_INDENT << strtTypesMap.at(key) << " " << StringTableFieldToString(key) << ";" << "  //+0x" << std::hex << offset << NEWLINE;

        strtBuf << "};" << NEWLINE;
        buf << strtBuf.str();
    }

    { //lua_Callbacks
        std::ostringstream cbBuf {};
        cbBuf << "struct lua_Callbacks {" << NEWLINE;

        std::ranges::sort(this->cbData.offsets.begin(), this->cbData.offsets.end(), [](auto& a, auto& b) -> bool {
            return a.second < b.second;
        });

        const std::unordered_map<cbField, const char*> cbElemsMap = {
            {cbField::userdata, "void* userdata"},
            {cbField::interrupt, "void(* interrupt)(lua_State* L, int gc)"},
            {cbField::panic, "void(* panic)(lua_State* L, int errcode)"}, //omitted from roblox build but here bc why not
            {cbField::userthread, "void(* userthread)(lua_State* LP, lua_State* L)"},
            {cbField::useratom, "int16_t(* useratom)(const char* s, size_t l)"},
            {cbField::debugbreak, "void(* debugbreak)(lua_State* L, lua_Debug* ar)"},
            {cbField::debugstep, "void(* debugstep)(lua_State* L, lua_Debug* ar)"},
            {cbField::debuginterrupt, "void(* debuginterrupt)(lua_State* L, lua_Debug* ar)"},
            {cbField::debugprotectederror, "void(* debugprotectederror)(lua_State* L)"},
            {cbField::onallocate, "void(* onallocate)(lua_State* L, size_t osize, size_t nsize)"}
        };

        for (const auto& [key, offset]: this->cbData.offsets) {
            cbBuf << TAB_INDENT << cbElemsMap.at(key) << ";" << "  //+0x" << std::hex << offset << NEWLINE;
        }

        cbBuf << "};" << NEWLINE << NEWLINE;
        buf << cbBuf.str();
    }

    { //lua_ExecutionCallbacks
        std::ostringstream ecbBuf {};
        ecbBuf << "struct lua_ExecutionCallbacks {" << NEWLINE;

        std::ranges::sort(this->ecbData.offsets.begin(), this->ecbData.offsets.end(), [](auto& a, auto& b) -> bool {
            return a.second < b.second;
        });

        const std::unordered_map<ExecCallbacksField, const char*> ecbElemsMap = {
            {ExecCallbacksField::context, "void* context"},
            {ExecCallbacksField::close, "void(* close)(lua_State* L)"},
            {ExecCallbacksField::destroy, "void(* destroy)(lua_State* L, Proto* proto)"},
            {ExecCallbacksField::enter, "void(* enter)(lua_State* L, Proto* proto)"},
            {ExecCallbacksField::disable, "void(* disable)(lua_State* L, Proto* proto)"},
            {ExecCallbacksField::getmemorysize, "size_t(* getmemorysize)(lua_State* L, Proto* proto)"},
            {ExecCallbacksField::gettypemapping, "uint8_t(* gettypemapping)(lua_State* L, const char* str, size_t len)"}
        };

        for (const auto& [key, offset]: this->ecbData.offsets) {
            ecbBuf << TAB_INDENT << ecbElemsMap.at(key) << ";" << "  //+0x" << std::hex << offset << NEWLINE;
        }

        ecbBuf << "};" << NEWLINE << NEWLINE;
        buf << ecbBuf.str();
    }

    std::ranges::sort(this->offsets.begin(), this->offsets.end(), [](auto& a, auto& b) -> bool {
        return a.second < b.second;
    });

    const std::unordered_map<GlobalStateField, const char*> typesMap = {
        {GlobalStateField::strt, "stringtable strt"},
        {GlobalStateField::frealloc, "void*(* frealloc)(void* ud, void* ptr, size_t osize, size_t nsize)"},
        {GlobalStateField::ud, "void* ud"},
        {GlobalStateField::currentwhite, "uint8_t currentwhite"},
        {GlobalStateField::gcstate, "uint8_t gcstate"},
        {GlobalStateField::gray, "GCObject* gray"},
        {GlobalStateField::grayagain, "GCObject* grayagain"},
        {GlobalStateField::weak, "GCObject* weak"},
        {GlobalStateField::GCthreshold, "size_t GCthreshold"},
        {GlobalStateField::totalbytes, "size_t totalbytes"},
        {GlobalStateField::gcgoal, "int gcgoal"},
        {GlobalStateField::gcstepmul, "int gcstepmul"},
        {GlobalStateField::gcstepsize, "int gcstepsize"},
        {GlobalStateField::freepages, "lua_Page* freepages[40]"},
        {GlobalStateField::freegcopages, "lua_Page* freegcopages[40]"},
        {GlobalStateField::allpages, "lua_Page* allpages"},
        {GlobalStateField::allgcopages, "lua_Page* allgcopages"},
        {GlobalStateField::sweepgcopage, "lua_Page* sweepgcopage"},
        {GlobalStateField::memcatbytes, "size_t memcatbytes[256]"},
        {GlobalStateField::mainthread, "lua_State* mainthread"},
        {GlobalStateField::uvhead, "UpVal uvhead"},
        {GlobalStateField::mt, "LuaTable* mt[11]"},
        {GlobalStateField::ttname, "TString* ttname[11]"},
        {GlobalStateField::tmname, "TString* tmname[21]"},
        {GlobalStateField::pseudotemp, "TValue pseudotemp"},
        {GlobalStateField::registry, "TValue registry"},
        {GlobalStateField::registryfree, "int registryfree"},
        {GlobalStateField::rngstate, "uint64_t rngstate"},
        {GlobalStateField::ptrenckey, "uint64_t ptrenckey[4]"},
        {GlobalStateField::cb, "lua_Callbacks cb"},
        {GlobalStateField::ecb, "lua_ExecutionCallbacks ecb"},
        {GlobalStateField::udatagc, "void(* udatagc[128])(lua_State*, void*)"},
        {GlobalStateField::udatamt, "LuaTable* udatamt[128]"},
        {GlobalStateField::lightuserdataname, "TString* lightuserdataname[128]"},
        {GlobalStateField::gcstats, "GCStats gcstats"},
        {GlobalStateField::gcmetrics, "#ifdef LUAI_GCMETRICS\n        GCMetrics gcmetrics;\n    #endif"}
    };

    buf << "struct global_State {" << NEWLINE;

    //calculate GCStats and GCMetrics positioning.
    constexpr size_t GCStats_size = 184;
    constexpr size_t GCMetrics_size = 456;

    ptrdiff_t gcStatsOffset   = -1;
    ptrdiff_t gcMetricsOffset = -1;



    for (size_t i = 0; i + 1 < offsets.size(); ++i) {
        ptrdiff_t gap = offsets[i + 1].second - offsets[i].second;

        //gcmetrics check
        if (gcMetricsOffset == -1 && gap >= GCMetrics_size - 32 && gap <= GCMetrics_size + 32) {
            gcMetricsOffset = offsets[i].second;
            continue;
        }

        //then gcstats check
        if (gcStatsOffset == -1 && gap >= GCStats_size - 32 && gap <= GCStats_size + 32)
            gcStatsOffset = offsets[i].second;
    }

    if (gcStatsOffset == -1 || gcMetricsOffset == -1)
        abort(); //idc lets just crash out


    //add each.
    for (const auto& [key, offset]: this->offsets) {
        buf << TAB_INDENT << typesMap.at(key) << ";" << "  //+0x" << std::hex << offset << NEWLINE;
    }

    buf << "};" << NEWLINE;

    return buf.str();
}