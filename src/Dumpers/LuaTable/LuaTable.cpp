/*
This file was created by 12345koip for the
LuGo Structure Dumper, a subproject of the
LuGo executor.

See LICENSE and README for details.
*/

#include "LuaTable.hpp"
#include <set>

using namespace LuDumper::Dumpers;
using namespace LuDumper::Dissassembler;

void LuaTableDumper::Scan() {
    puts("Dumping LuaTable...");
    auto& Dissassembler = Dissassembler::Dissassembler::GetSingleton();

    const auto setarrayvector_signature = hat::parse_signature(setarrayvector).value();
    const auto setnodevector_signature = hat::parse_signature(setnodevector).value();
    const auto luaH_new_signature = hat::parse_signature(luaH_new).value();
    const auto luaV_settable_signature = hat::parse_signature(luaV_settable).value();
    const auto luaT_gettmbyobj_signature = hat::parse_signature(luaT_gettmbyobj).value();

    { //setarrayvector.
        puts("Scanning for setarrayvector...");

        //get setarrayvector disasm.
        auto setarrayvector_match = hat::find_pattern(setarrayvector_signature, ".text");
        if (!setarrayvector_match.has_result()) fail("setarrayvector");

        printf("setarrayvector @ %p\n", setarrayvector_match.get());

        //bounds of function
        uint8_t* start = reinterpret_cast<uint8_t*>(setarrayvector_match.get());
        uint8_t* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x80
        );
        
        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        //second call is to luaM_realloc_, appears first in disasm, passing lua state, table, array ptr, sizearray, and other bits
        //we need to look at the last state of rdx and r8 to get these
        const auto reallocCall = instructionList.GetInstructionWhichMatches("call", "", true);
        const auto reallocIt = instructionList.GetInstructionPosition(*reallocCall);

        const AsmInstruction* arrayIns = nullptr;
        const AsmInstruction* sizearrayIns = nullptr;
        
        //we are looking for the first two variations of mov, one into rdx and one into r8
        log_search("mov ..., ...");
        for (auto it = reallocIt; it != instructionList.begin() && it != reallocIt - 10 && (!arrayIns || !sizearrayIns); --it) {
            const AsmInstruction& ins = *it;

            if (ins.mnemonic.find("mov") == std::string::npos) continue;

            if (ins.detail[0]->reg == X86_REG_RDX || ins.detail[0]->reg == X86_REG_EDX)
                arrayIns = &ins;
            else if (ins.detail[0]->reg == X86_REG_R8 || ins.detail[0]->reg == X86_REG_R8D)
                sizearrayIns = &ins;
        }

        LUDUMP_ASSERT(arrayIns != nullptr, "could not get array offset");
        LUDUMP_ASSERT(sizearrayIns != nullptr, "could not get sizearray offset");

        const auto arrayOffset = arrayIns->detail[1]->disp;
        log_offset(LuaTableFieldToString(LuaTableField::array), arrayOffset);
        this->offsets.emplace_back(LuaTableField::array, arrayOffset);

        const auto sizearrayOffset = sizearrayIns->detail[1]->disp;
        log_offset(LuaTableFieldToString(LuaTableField::sizearray), sizearrayOffset);
        this->offsets.emplace_back(LuaTableField::sizearray, sizearrayOffset);
    }

    { //setnodevector.
        puts("Scanning for setnodevector...");

        //get setnodevector disasm.
        auto setnodevector_match = hat::find_pattern(setnodevector_signature, ".text");
        if (!setnodevector_match.has_result()) fail("setnodevector");

        printf("setnodevector @ %p\n", setnodevector_match.get());

        //bounds of function
        uint8_t* start = reinterpret_cast<uint8_t*>(setnodevector_match.get());
        uint8_t* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x120
        );
        
        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        log_search("mov qword ptr [rdx + 0x??], ...");
        const auto nodeIns = instructionList.GetInstructionWhichMatches("mov", "qword ptr [rdx", true);
        const auto nodeOffset = nodeIns->detail[0]->disp;
        log_offset(LuaTableFieldToString(LuaTableField::node), nodeOffset);
        this->offsets.emplace_back(LuaTableField::node, nodeOffset);



        log_search("mov ... [... + 0x??], ...");
        const auto allMovs = instructionList.GetAllInstructionsWhichMatch("mov", "], ", true);

        const auto sizenodeIns = allMovs[7];
        const auto sizenodeOffset = sizenodeIns->detail[0]->disp;
        log_offset(LuaTableFieldToString(LuaTableField::lsizenode), sizenodeOffset);
        this->offsets.emplace_back(LuaTableField::lsizenode, sizenodeOffset);

        const auto nodefreeIns = allMovs[8];
        const auto nodefreeOffset_fromBase = nodefreeIns->detail[0]->disp;
        log_offset("[union]::lastfree", nodefreeOffset_fromBase);
        this->unionData.unionOffsets.emplace_back(lt_unionField::lastfree, nodefreeOffset_fromBase);

        //union of same data type, so same size
        log_offset("[union]::aboundary", nodefreeOffset_fromBase);
        this->unionData.unionOffsets.emplace_back(lt_unionField::aboundary, nodefreeOffset_fromBase);


        const auto nodemask8Ins = allMovs[9];
        const auto nodemask8Offset = nodemask8Ins->detail[0]->disp;
        log_offset(LuaTableFieldToString(LuaTableField::nodemask8), nodemask8Offset);
        this->offsets.emplace_back(LuaTableField::nodemask8, nodemask8Offset);
    }

    { //luaV_settable.
        puts("Scanning for luaV_settable...");

        //get luaV_settable disasm.
        auto luaV_settable_match = hat::find_pattern(luaV_settable_signature, ".text");
        if (!luaV_settable_match.has_result()) fail("luaV_settable");

        printf("luaV_settable @ %p\n", luaV_settable_match.get());

        //bounds of function
        uint8_t* start = reinterpret_cast<uint8_t*>(luaV_settable_match.get());
        uint8_t* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x120
        );
        
        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);





        log_search("cmp byte ptr [rdi + 0x??], 0");
        const auto readonlyIns = instructionList.GetInstructionWhichMatches("cmp", "byte ptr [rdi + 0x??], 0", false);
        const auto readonlyOffset = readonlyIns->detail[0]->disp;
        log_offset(LuaTableFieldToString(LuaTableField::readonly), readonlyOffset);
        this->offsets.emplace_back(LuaTableField::readonly, readonlyOffset);

        log_search("mov byte ptr [... + 0x??], 0");
        const auto tmcacheIns = instructionList.GetInstructionWhichMatches("mov", "], 0", true);
        const auto tmcacheOffset = tmcacheIns->detail[0]->disp;
        log_offset(LuaTableFieldToString(LuaTableField::tmcache), tmcacheOffset);
        this->offsets.emplace_back(LuaTableField::tmcache, tmcacheOffset);
    }

    { //luaT_gettmbyobj.
        puts("Scanning for luaT_gettmbyobj...");

        //get luaT_gettmbyobj disasm.
        auto luaT_gettmbyobj_match = hat::find_pattern(luaT_gettmbyobj_signature, ".text");
        if (!luaT_gettmbyobj_match.has_result()) fail("luaT_gettmbyobj");

        printf("luaT_gettmbyobj @ %p\n", luaT_gettmbyobj_match.get());

        //bounds of function
        uint8_t* start = reinterpret_cast<uint8_t*>(luaT_gettmbyobj_match.get());
        uint8_t* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x120
        );
        
        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);


        log_search("cmp byte ptr [... + 0x??], 6");
        const auto ttblCmpInsPos = instructionList.GetInstructionPosition("cmp", ", 6", true);
        const auto jmpInsPos = ttblCmpInsPos + 1;
        const auto jmpTarget = jmpInsPos->detail[0]->imm;
        const uint8_t* byte1 = reinterpret_cast<uint8_t*>(jmpTarget) + 3; //skip the first mov.

        const std::vector<uint8_t> bytes = {
            *byte1,
            *(byte1 + 1),
            *(byte1 + 2),
            *(byte1 + 3)
        };

        const auto matchingIns = instructionList.GetInstructionByBytes(bytes);
        LUDUMP_ASSERT(matchingIns != nullptr, "could not get mov instruction for metatable");

        const auto mtOffset = matchingIns->detail[1]->disp;
        log_offset(LuaTableFieldToString(LuaTableField::metatable), mtOffset);
        this->offsets.emplace_back(LuaTableField::metatable, mtOffset);
    }


    { //luaH_new.
        puts("Scanning for luaH_new...");

        //get luaH_new disasm.
        auto luaH_new_match = hat::find_pattern(luaH_new_signature, ".text");
        if (!luaH_new_match.has_result()) fail("luaH_new");

        printf("luaH_new @ %p\n", luaH_new_match.get());

        //bounds of function
        uint8_t* start = reinterpret_cast<uint8_t*>(luaH_new_match.get());
        uint8_t* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x80
        );
        
        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);


        log_search("mov byte ptr [rax + 0x??], ...");
        const auto allMovBytePtr = instructionList.GetAllInstructionsWhichMatch("mov", "byte ptr [rax", true);
        const LuaTableField fields[3] = {LuaTableField::tt, LuaTableField::marked, LuaTableField::memcat};

        for (int i = 0; i < 3; ++i) {
            const LuaTableField field = fields[i];
            const AsmInstruction* ins = allMovBytePtr[i];

            const auto offset = ins->detail[0]->disp;
            log_offset(LuaTableFieldToString(field), offset);
            this->offsets.emplace_back(field, offset);
        }
    }

    //last two are safeenv and gclist respectively, idk if they are even shuffling
    //LuaTable rn, if they are then ill change it later lmao
    // puts("Calculating safeenv and gclist...");


    // std::set<ptrdiff_t> occupied;
    // for (auto& [field, off]: this->offsets) occupied.insert(off);
    // for (auto& [uf, off]: this->unionData.unionOffsets) occupied.insert(off);

    // std::vector<ptrdiff_t> freeSlots;
    // for (ptrdiff_t off = 0x8; off < 0x64; off += 8)
    //     if (!occupied.count(off))
    //         freeSlots.push_back(off);

    // LUDUMP_ASSERT(freeSlots.size() == 2, "expected exactly two free slots");

    // ptrdiff_t gclistOffset = 0x64 - 8;
    // auto it = std::find(freeSlots.begin(), freeSlots.end(), gclistOffset);
    // LUDUMP_ASSERT(it != freeSlots.end(), "gclist slot not found");
    // freeSlots.erase(it);

    // ptrdiff_t safeenvOffset = freeSlots.front();

    // log_offset("safeenv", safeenvOffset);
    // this->offsets.emplace_back(LuaTableField::safeenv, safeenvOffset);

    // log_offset("gclist", gclistOffset);
    // this->offsets.emplace_back(LuaTableField::gclist, gclistOffset);
}

std::string LuaTableDumper::ToHeaderContents() {
    return "";
}