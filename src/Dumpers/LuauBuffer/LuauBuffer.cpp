/*
This file was created by 12345koip for the
LuGo Structure Dumper, a subproject of the
LuGo executor.

See LICENSE and README for details.
*/

#include "LuauBuffer.hpp"
#include <set>

using namespace LuDumper::Dumpers;
using namespace LuDumper::Dissassembler;

void LuauBufferDumper::Scan() {
    puts("Dumping LuauBuffer...");
    auto& Dissassembler = Dissassembler::Dissassembler::GetSingleton();

    const auto luaB_newbuffer_signature = hat::parse_signature(luaB_newbuffer).value();

    {
        puts("Scanning for luaB_newbuffer...");

        //get luaB_newbuffer disasm.
        auto luaB_newbuffer_match = hat::find_pattern(luaB_newbuffer_signature, ".text");
        if (!luaB_newbuffer_match.has_result()) fail("luaB_newbuffer");

        printf("luaB_newbuffer @ %p\n", luaB_newbuffer_match.get());

        //bounds of function
        uint8_t* start = reinterpret_cast<uint8_t*>(luaB_newbuffer_match.get());
        uint8_t* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x180
        );
        
        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        

        //tt, marked and memcat are all exposed by the byte ptr moves
        log_search("mov byte ptr [rax + 0x??], ...");
        const auto allMovRax = instructionList.GetAllInstructionsWhichMatch("mov", "byte ptr [rax", true);
        const LuauBufferField movBytePtrFields[3] = {LuauBufferField::tt, LuauBufferField::marked, LuauBufferField::memcat};

        for (int i = 0; i < 3; ++i) {
            const LuauBufferField field = movBytePtrFields[i];
            const AsmInstruction* ins = allMovRax[i];

            const auto offset = ins->detail[0]->disp;
            log_offset(LuauBufferFieldToString(field), offset);
            this->offsets.emplace_back(field, offset);
        }


        //len is exposed by the only mov dword ptr
        log_search("mov dword ptr [rax + 0x??], ...");
        const auto lenIns = instructionList.GetInstructionWhichMatches("mov", "dword ptr [rax", true);
        const auto lenOffset = lenIns->detail[0]->disp;
        log_offset(LuauBufferFieldToString(LuauBufferField::len), lenOffset);
        this->offsets.emplace_back(LuauBufferField::len, lenOffset);


        //the second call ins is the call to memset (with data as arg 1),
        //so we can walk back and look for the first lea into rcx to find data
        const auto secondCall = instructionList.GetAllInstructionsWhichMatch("call", "", true)[1];
        const auto secondCallPos = instructionList.GetInstructionPosition(*secondCall, true);

        const AsmInstruction* leaIns = nullptr;
        for (auto it = secondCallPos; it != instructionList.begin() && it != secondCallPos - 5; --it) {
            if (it->mnemonic == "lea" && it->operands.find("rcx, [rax +") != std::string::npos) {
                leaIns = &(*it);
                break;
            }
        }

        LUDUMP_ASSERT(leaIns != nullptr, "could not find lea before memset");

        const auto dataOffset = leaIns->detail[1]->disp;
        log_offset(LuauBufferFieldToString(LuauBufferField::data), dataOffset);
        this->offsets.emplace_back(LuauBufferField::data, dataOffset);
    }

    log_finish("LuauBuffer");
}

std::string LuauBufferDumper::ToHeaderContents() {
    static const std::unordered_map<LuauBufferField, const char*> typesMap = {
        {LuauBufferField::tt, "uint8_t"},
        {LuauBufferField::marked, "uint8_t"},
        {LuauBufferField::memcat, "uint8_t"},
        {LuauBufferField::len, "unsigned int"},
        {LuauBufferField::data, decl_array_align("char", "1", "8")}
    };

    std::sort(this->offsets.begin(), this->offsets.end(), [](const auto& a, const auto& b) -> bool {
        return a.second < b.second;
    });

    std::ostringstream buf {};
    buf << "struct LuauBuffer {" << NEWLINE;

    for (const auto& [key, offset]: this->offsets) {
        const char* type = typesMap.at(key);
        buf << TAB_INDENT;

        if (strstr(type, "ARR") != nullptr)
            buf << parse_decl_array(type, LuauBufferFieldToString(key));
        else
            buf << type << " " << LuauBufferFieldToString(key);
        
        buf << ";" << "  //+0x" << std::hex << offset << NEWLINE;
    }

    buf << "};";

    return buf.str();
}