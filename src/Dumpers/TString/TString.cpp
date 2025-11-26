/*
This file was created by 12345koip for the
LuGo Structure Dumper, a subproject of the
LuGo executor.

See LICENSE and README for details.
*/

#include "TString.hpp"

using namespace LuDumper::Dumpers;
using namespace LuDumper::Dissassembler;

void TStringDumper::Scan() {
    puts("Dumping TString...");
    auto& Dissassembler = Dissassembler::Dissassembler::GetSingleton();

    //all the fields are exposed in luaS_newlstr, and newlstr is inlined
    //(not luaS_newlstr, just newlstr) so we only need to dissassemble the main func
    const auto luaS_newlstr_signature = hat::parse_signature(luaS_newlstr).value();

    {
        puts("Scanning for luaS_newlstr...");

        //get luaS_newlstr disasm.
        auto luaS_newlstr_match = hat::find_pattern(luaS_newlstr_signature, ".text");
        if (!luaS_newlstr_match.has_result()) fail("luaS_newlstr");

        printf("luaS_newlstr @ %p\n", luaS_newlstr_match.get());

        //bounds of function
        uint8_t* start = reinterpret_cast<uint8_t*>(luaS_newlstr_match.get());
        uint8_t* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x180
        );
        
        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);


        //tt, marked and memcat are exposed in luaC_init.

        //tt is exposed by the only mov of 0x5 (LUA_TSTRING) into an object
        log_search("mov byte ptr [... + 0x??], 5");
        const auto ttIns = instructionList.GetInstructionWhichMatches("mov", "], 5", true);
        const auto ttOffset = ttIns->detail[0]->disp;
        log_offset(TStringFieldToString(TStringField::tt), ttOffset);
        this->offsets.emplace_back(TStringField::tt, ttOffset);

        //for marked, we can look for the second 'and' with 0x3 (the first one is pre-loop),
        //then the first 'mov' following it that uses the same register as source.
        {
            //there are two and instructions, but the one we don't want is not immediately followed by a mov.
            std::vector<AsmInstruction>::const_iterator bandInsPos = instructionList.end();

            log_search("and ..., 0x3");
            for (const auto& andIns: instructionList.GetAllInstructionsWhichMatch("and", "3", true)) {
                const auto pos = instructionList.GetInstructionPosition(*andIns);
                const auto& nextIns = pos + 1;

                if (nextIns->mnemonic != "mov") continue;
                bandInsPos = pos;
                break;
            }

            LUDUMP_ASSERT(bandInsPos != instructionList.end(), "could not find desired and ins");
            const auto markedReg = bandInsPos->detail[0]->reg;

            //we need to look for the first mov following this instruction
            //which uses the same register. It should be close.
            const AsmInstruction* markedIns = nullptr;

            log_search("mov byte ptr [... + 0x??], ...");
            for (auto it = bandInsPos; it != instructionList.end() && it != bandInsPos + 10; ++it) {
                if (it->mnemonic == "mov" && it->detail[1]->reg == markedReg) {
                    markedIns = &(*it); //sigh
                    break;
                }
            }

            LUDUMP_ASSERT(markedIns != nullptr, "could not find mov of marked into slot");
            
            //otherwise, we have it
            const auto markedOffset = markedIns->detail[0]->disp;
            log_offset(TStringFieldToString(TStringField::marked), markedOffset);
            this->offsets.emplace_back(TStringField::marked, markedOffset);
        }


        //for memcat, we want a movzx byte ptr from the Lua state (activememcat)
        //into a register, followed by a mov which also uses byte ptr.
        {
            log_search("movzx ..., byte ptr [... + 0x??]");
            const auto allMoves = instructionList.GetAllInstructionsWhichMatch("movzx", "byte ptr [", true);
            const AsmInstruction* memcatIns = nullptr;

            log_search("mov byte ptr [... + 0x??], ...");
            for (const auto& movIns: allMoves) {
                const auto insPos = instructionList.GetInstructionPosition(*movIns);
                const auto nextInsPos = insPos + 1;
                if (nextInsPos == instructionList.end() || nextInsPos->detail.size() < 2) continue;

                const auto regUsed = insPos->detail[0]->reg;
                if (nextInsPos->operands.find("byte ptr [") == std::string::npos || nextInsPos->mnemonic.find("mov") == std::string::npos) continue;
                memcatIns = &(*nextInsPos);
            }

            LUDUMP_ASSERT(memcatIns != nullptr, "failed to find memcat ins");

            const auto memcatOffset = memcatIns->detail[0]->disp;
            log_offset(TStringFieldToString(TStringField::memcat), memcatOffset);
            this->offsets.emplace_back(TStringField::memcat, memcatOffset);
        }


        //ts->atom is exposed by the constant 0xFFFF8000, which is the two's complement
        //representation of -32768, aka ATOM_UNDEF.
        log_search("mov dword ptr [... + 0x??], 0xffff8000");
        const auto atomIns = instructionList.GetInstructionWhichMatches("mov", "0xffff8000", true);
        const auto atomOffset = atomIns->detail[0]->disp;
        log_offset(TStringFieldToString(TStringField::atom), atomOffset);
        this->offsets.emplace_back(TStringField::atom, atomOffset);

        //multiple fields are exposed by the mov dword ptr pattern.
        {
            log_search("mov dword ptr [... + 0x??], ...");
            const auto allMovDwordPtr = instructionList.GetAllInstructionsWhichMatch("mov", "dword ptr [", true);

            //we only want instructions where the memory offset is the destination.
            auto filteredMovDwordPtr = allMovDwordPtr | std::ranges::views::filter([](const AsmInstruction* e) -> bool {
                return e->operands.starts_with("dword ptr");
            });

            //of these filtered ones, the first instruction will be the atom, second hash, third len.
            const TStringField viewFields[] = {TStringField::atom, TStringField::hash, TStringField::len};
            int i = 0;

            for (auto&& ins: filteredMovDwordPtr) {
                const auto field = viewFields[i];

                if (field != TStringField::atom) {
                    const auto offset = ins->detail[0]->disp;
                    log_offset(TStringFieldToString(field), offset);
                    this->offsets.emplace_back(field, offset);
                }

                ++i;
            }
        }


        //for next, we want the first mov into a register from the same register plus disp.
        log_search("mov x, [x + 0x??]");
        const auto allMov = instructionList.GetAllInstructionsWhichMatch("mov", "qword ptr [", true);

        for (const auto& ins: allMov) {
            if (ins->mnemonic == "mov" && ins->detail[1]->type == X86_OP_MEM && ins->detail[0]->reg == ins->detail[1]->base && ins->detail[1]->index == X86_REG_INVALID && ins->detail[1]->disp != 0) {
                //we found it
                const auto offset = ins->detail[1]->disp;
                log_offset(TStringFieldToString(TStringField::next), offset);
                this->offsets.emplace_back(TStringField::next, offset);

                break;
            }
        }

        //for data, we just need to find a lea into rcx before the call to memcpy.
        log_search("lea rcx, [... + 0x??]");
        const auto dataIns = instructionList.GetInstructionWhichMatches("lea", "rcx, [", true);
        const auto dataOffset = dataIns->detail[1]->disp;
        log_offset(TStringFieldToString(TStringField::data), dataOffset);
        this->offsets.emplace_back(TStringField::data, dataOffset);
    }

    log_finish("TString");
}

std::string TStringDumper::ToHeaderContents() {
    static const std::unordered_map<TStringField, const char*> typesMap = {
        {TStringField::tt, "uint8_t"},
        {TStringField::marked, "uint8_t"},
        {TStringField::memcat, "uint8_t"},
        {TStringField::atom, "int16_t"},
        {TStringField::next, "TString*"},
        {TStringField::hash, "unsigned int"},
        {TStringField::len, "unsigned int"},
        {TStringField::data, decl_array("char", "1")}
    };

    std::sort(this->offsets.begin(), this->offsets.end(), [](const auto& a, const auto& b) -> bool {
        return a.second < b.second;
    });



    std::ostringstream buf;
    buf << "struct TString {" << NEWLINE;

    for (const auto& [key, offset]: this->offsets) {
        const char* type = typesMap.at(key);
        buf << TAB_INDENT;

        if (strstr(type, "ARR") != nullptr) //space = array fmt.
            buf << parse_decl_array(type, TStringFieldToString(key));
        else
            buf << type << " " << TStringFieldToString(key);
        
        buf << ";" << "  //+0x" << std::hex << offset << NEWLINE;
    }

    buf << "};";
    return buf.str();
}