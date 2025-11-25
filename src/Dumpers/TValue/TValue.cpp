/*
This file was created by 12345koip for the
LuGo Structure Dumper, a subproject of the
LuGo executor.

See LICENSE and README for details.
*/

#include "TValue.hpp"
#include <set>

using namespace LuDumper::Dumpers;
using namespace LuDumper::Dissassembler;

void TValueDumper::Scan() {
    puts("Dumping TValue...");
    auto& Dissassembler = Dissassembler::Dissassembler::GetSingleton();

    //both tt and value are accessed in luaT_gettmbyobj,
    //since we know the size is 0x10 always we can just
    //infer the last slot to be extra.

    //signature
    const auto luaT_gettmbyobj_signature = hat::parse_signature(luaT_gettmbyobj).value();

    {
        puts("Scanning for luaT_gettmbyobj...");

        //get luaT_gettmbyobj disasm.
        auto luaT_gettmbyobj_match = hat::find_pattern(luaT_gettmbyobj_signature, ".text");
        if (!luaT_gettmbyobj_match.has_result()) fail("luaT_gettmbyobj");

        printf("luaT_gettmbyobj @ %p\n", luaT_gettmbyobj_match.get());

        //bounds of function
        uint8_t* start = reinterpret_cast<uint8_t*>(luaT_gettmbyobj_match.get());
        uint8_t* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x180
        );
        
        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);



        //the first movsxd, which is probably the first instruction of the function,
        //exposes tt. let's get the first one of that opcode just in case...
        log_search("movsxd ..., dword ptr [... + 0x??]");
        const auto& first_movsxd = instructionList.GetInstructionWhichMatches("movsxd", "", true);
        const auto ttOffset = first_movsxd->detail[1]->disp;
        log_offset(TValueFieldToString(TValueField::tt), ttOffset);
        this->offsets.emplace_back(TValueField::tt, ttOffset);
        
        //value is exposed when rcx is operated on in a mov.
        log_search("mov ..., qword ptr [rdx + 0x??]");
        const auto& valueIns = instructionList.GetInstructionWhichMatches("mov", "qword ptr [rdx", true);
        const auto valueOffset = valueIns->detail[1]->disp;
        log_offset(TValueFieldToString(TValueField::value), valueOffset);
        this->offsets.emplace_back(TValueField::value, valueOffset);

        //calculate where extra should sit
        //LUA_EXTRA_SIZE expands to 1 so we are looking for 4 bytes
        puts("Calculating offset: \"extra\"...");
        constexpr ptrdiff_t slots[4] = {0x00, 0x04, 0x08, 0x0C};
        std::set<ptrdiff_t> occupied {};

        occupied.insert(valueOffset);
        occupied.insert(valueOffset + 4);
        occupied.insert(ttOffset);

        ptrdiff_t extraOffset = 0;

        for (const auto s: slots) {
            if (!occupied.count(s)) {
                extraOffset = s;
                break;
            }
        }

        log_offset(TValueFieldToString(TValueField::extra), extraOffset);
        this->offsets.emplace_back(TValueField::extra, extraOffset);
    }
}

std::string TValueDumper::ToHeaderContents() {
    //types map.
    static const std::unordered_map<TValueField, const char*> typesMap = {
        {TValueField::extra, decl_array("int", "1")},
        {TValueField::tt, "uint8_t"},
        {TValueField::value, "Value"}
    };

    std::sort(this->offsets.begin(), this->offsets.end(), [](const auto& a, const auto& b) -> bool {
        return a.second < b.second;
    });

    std::ostringstream buf {};
    buf << "struct TValue {" << NEWLINE;

    for (const auto& [key, offset]: this->offsets) {
        const char* type = typesMap.at(key);
        buf << TAB_INDENT;

        if (strchr(type, ' ') != nullptr) //space = array fmt.
            buf << parse_decl_array(type, TValueFieldToString(key));
        else
            buf << type << " " << TValueFieldToString(key);
        
        buf << ";" << "  //+0x" << std::hex << offset << NEWLINE;
    }

    buf << "};";
    return buf.str();
}