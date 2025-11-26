/*
This file was created by 12345koip for the
LuGo Structure Dumper, a subproject of the
LuGo executor.

See LICENSE and README for details.
*/

#include "Udata.hpp"
#include <set>

using namespace LuDumper::Dumpers;
using namespace LuDumper::Dissassembler;

void UdataDumper::Scan() {
    puts("Dumping Udata...");
    auto& Dissassembler = Dissassembler::Dissassembler::GetSingleton();

    const auto luaU_newudata_signature = hat::parse_signature(luaU_newudata).value();

    {
        puts("Scanning for luaU_newudata...");

        //get luaU_newudata disasm.
        auto luaU_newudata_match = hat::find_pattern(luaU_newudata_signature, ".text");
        if (!luaU_newudata_match.has_result()) fail("luaU_newudata");

        printf("luaU_newudata @ %p\n", luaU_newudata_match.get());

        //bounds of function
        uint8_t* start = reinterpret_cast<uint8_t*>(luaU_newudata_match.get());
        uint8_t* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x180
        );
        
        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);



        //u->tt is exposed by the mov of 8, which is LUA_TUSERDATA
        log_search("mov byte ptr [... + 0x??], 8");
        const auto ttIns = instructionList.GetInstructionWhichMatches("mov", "], 8", true);
        const auto ttOffset = ttIns->detail[0]->disp;
        log_offset(UdataFieldToString(UdataField::tt), ttOffset);
        this->offsets.emplace_back(UdataField::tt, ttOffset);

        //there are 3 instructions which mov with byte ptr and rax, in the order of marked, tag and memcat.
        log_search("mov byte ptr [rax + 0x??], ...");
        const auto allMovBytePtr = instructionList.GetAllInstructionsWhichMatch("mov", "byte ptr [rax +", true);
        const UdataField movBytePtrFields[3] = {UdataField::marked, UdataField::tag, UdataField::memcat};

        for (int i = 0; i < 3; ++i) {
            const AsmInstruction* ins = allMovBytePtr[i];
            const UdataField field = movBytePtrFields[i];

            const auto offset = ins->detail[0]->disp;
            log_offset(UdataFieldToString(field), offset);
            this->offsets.emplace_back(field, offset);
        }


        //the only mov into a rax offset with a dword ptr is the len
        log_search("mov dword ptr [rax + 0x??], ...");
        const auto lenIns = instructionList.GetInstructionWhichMatches("mov", "dword ptr [rax +", true);
        const auto lenOffset = lenIns->detail[0]->disp;
        log_offset(UdataFieldToString(UdataField::len), lenOffset);
        this->offsets.emplace_back(UdataField::len, lenOffset);

        //likewise, the only mov into a rax offset with a qword ptr is the metatable
        log_search("mov qword ptr [rax + 0x??], ...");
        const auto mtIns = instructionList.GetInstructionWhichMatches("mov", "qword ptr [rax +", true);
        const auto mtOffset = mtIns->detail[0]->disp;
        log_offset(UdataFieldToString(UdataField::metatable), mtOffset);
        this->offsets.emplace_back(UdataField::metatable, mtOffset);



        //we can look at what slots are free to figure out where data sits.
        puts("Calculating offset: \"data\"...");
        constexpr ptrdiff_t slots[] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x8, 0x10};
        std::set<ptrdiff_t> occupied {};

        for (const auto& [_key, offset]: this->offsets)
            occupied.insert(offset);
        
        ptrdiff_t dataOffset = 0;

        for (const auto s: slots) {
            if (!occupied.count(s)) {
                dataOffset = s;
                break;
            }
        }

        LUDUMP_ASSERT(dataOffset != 0, "failed to calculate data offset");
        
        log_offset(UdataFieldToString(UdataField::data), dataOffset);
        this->offsets.emplace_back(UdataField::data, dataOffset);
    }

    log_finish("Udata");
}

std::string UdataDumper::ToHeaderContents() {
    static const std::unordered_map<UdataField, const char*> typesMap = {
        {UdataField::tt, "uint8_t"},
        {UdataField::marked, "uint8_t"},
        {UdataField::memcat, "uint8_t"},
        {UdataField::tag, "uint8_t"},
        {UdataField::len, "int"},
        {UdataField::metatable, "LuaTable*"},
        {UdataField::data, decl_array_align("char", "1", "8")}
    };

    std::sort(this->offsets.begin(), this->offsets.end(), [](const auto& a, const auto& b) -> bool {
        return a.second < b.second;
    });



    std::ostringstream buf {};
    buf << "struct Udata {" << NEWLINE;

    for (const auto& [key, offset]: this->offsets) {
        const char* type = typesMap.at(key);
        buf << TAB_INDENT;

        if (strstr(type, "ARR") != nullptr)
            buf << parse_decl_array(type, UdataFieldToString(key));
        else
            buf << type << " " << UdataFieldToString(key);
        
        buf << ";" << "  //+0x" << std::hex << offset << NEWLINE;
    }

    buf << "};";
    return buf.str();
}