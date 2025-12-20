/*
This file was created by 12345koip for the
LuGo Structure Dumper, a subproject of the
LuGo executor.

See LICENSE and README for details.
*/

#include "Closure.hpp"
#include <set>

using namespace LuDumper::Dumpers;
using namespace LuDumper::Dissassembler;

#define insert_union2base(set, offs) if (!set.count(offs)) set.insert(offs)

void ClosureDumper::Scan() {
    puts("Dumping Closure...");
    auto& Dissassembler = Dissassembler::Dissassembler::GetSingleton();

    const auto luaF_newCclosure_signature = hat::parse_signature(luaF_newCclosure).value();
    const auto lua_pushcclosurek_signature = hat::parse_signature(lua_pushcclosurek).value();
    const auto luaF_newLclosure_signature = hat::parse_signature(luaF_newLclosure).value();

    {
        puts("Scanning for luaF_newCclosure...");

        //get luaF_newCclosure disasm.
        auto luaF_newCclosure_match = hat::find_pattern(luaF_newCclosure_signature, ".text");
        if (!luaF_newCclosure_match.has_result()) fail("luaF_newCclosure");

        printf("luaF_newCclosure @ %p\n", luaF_newCclosure_match.get());

        //bounds of function
        uint8_t* start = reinterpret_cast<uint8_t*>(luaF_newCclosure_match.get());
        uint8_t* end = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(start) + 0x80
        );
        
        const auto instructionList = *Dissassembler.Dissassemble(start, end, true);

        //the only mov word ptr is isC.
        log_search("mov word ptr [rax + 0x??], 1");
        const auto iscIns = instructionList.GetInstructionWhichMatches("mov", "word ptr [rax + 0x??], 1");
        const auto iscOffset = iscIns->detail[0]->disp;
        log_offset(ClosureFieldToString(ClosureField::isC), iscOffset);
        this->offsets.emplace_back(ClosureField::isC, iscOffset);

        //multiple offsets are exposed by the mov byte ptr into rax, just like before.
        log_search("mov byte ptr [rax + 0x??], ...");
        const auto allMovBytePtr = instructionList.GetAllInstructionsWhichMatch("mov", "byte ptr [rax", true);
        constexpr ClosureField fields[4] = {ClosureField::tt, ClosureField::marked, ClosureField::memcat, ClosureField::nupvalues};

        for (int i = 0; i < 4; ++i) {
            const ClosureField field = fields[i];
            const AsmInstruction* ins = allMovBytePtr[i];

            const auto offset = ins->detail[0]->disp;
            log_offset(ClosureFieldToString(field), offset);
            this->offsets.emplace_back(field, offset);
        }

        //multiple are also exposed by the qword ptr mov into rax as well
        log_search("mov qword ptr [rax + 0x??], ...");
        const auto allMovQwordPtr = instructionList.GetAllInstructionsWhichMatch("mov", "qword ptr [rax", true);

        //this gives us c.f, c.cont, debugname and env. we only really need env lmao we can get the others more securely
        const AsmInstruction* envIns = allMovQwordPtr[3];
        const auto envOffset = envIns->detail[0]->disp;
        log_offset(ClosureFieldToString(ClosureField::env), envOffset);
        this->offsets.emplace_back(ClosureField::env, envOffset);

        

        //------------
        { //extra
            puts("analysing C union...");
            
            //----
            puts("Scanning for lua_pushcclosurek...");

            //get lua_pushcclosurek disasm.
            auto lua_pushcclosurek_match = hat::find_pattern(lua_pushcclosurek_signature, ".text");
            if (!lua_pushcclosurek_match.has_result()) fail("lua_pushcclosurek");

            printf("lua_pushcclosurek @ %p\n", lua_pushcclosurek_match.get());

            //bounds of function
            uint8_t* startl = reinterpret_cast<uint8_t*>(lua_pushcclosurek_match.get());
            uint8_t* endl = reinterpret_cast<uint8_t*>(
                reinterpret_cast<uintptr_t>(start) + 0x80
            );
            
            const auto lpcck_instructionList = *Dissassembler.Dissassemble(startl, endl, true);



            const auto fIns = allMovQwordPtr[0];
            const auto fOffset_fromBase = fIns->detail[0]->disp;

            const auto contIns = allMovQwordPtr[1];
            const auto contOffset_fromBase = contIns->detail[0]->disp;

            const auto debugnameIns = allMovQwordPtr[2];
            const auto debugnameOffset_fromBase = debugnameIns->detail[0]->disp;
            
            //upvals
            log_search("movups xmmword ptr [...], ...");
            const auto upvalsIns = lpcck_instructionList.GetAllInstructionsWhichMatch("movups", "xmmword ptr [", true)[1];
            const auto upvalsOffset_fromBase = upvalsIns->detail[0]->disp;


            //gather all offsets and sort them. the lowest offset is the base of the union.
            std::array<ptrdiff_t, 4> cUnionOffsets = {fOffset_fromBase, contOffset_fromBase, debugnameOffset_fromBase, upvalsOffset_fromBase};
            const auto unionOffset = *std::min_element(cUnionOffsets.begin(), cUnionOffsets.end());

            log_offset("c and l union", unionOffset);
            this->unionData.unionOffset = unionOffset;


            const c_unionField uFields[4] = {c_unionField::f, c_unionField::cont, c_unionField::debugname, c_unionField::upvals};
            for (int i = 0; i < 4; ++i) {
                const auto e = cUnionOffsets[i];
                const auto offsetFromUnion = e - unionOffset;

                log_offset(CUnionFieldToString(uFields[i]), offsetFromUnion);
                this->unionData.cClosureFields.emplace_back(uFields[i], offsetFromUnion);
            }


            //l bits
            puts("Scanning for luaF_newLclosure...");

            //get luaF_newLclosure disasm.
            auto luaF_newLclosure_match = hat::find_pattern(luaF_newLclosure_signature, ".text");
            if (!luaF_newLclosure_match.has_result()) fail("luaF_newLclosure");

            printf("luaF_newLclosure @ %p\n", luaF_newLclosure_match.get());

            //bounds of function
            uint8_t* startlfc = reinterpret_cast<uint8_t*>(luaF_newLclosure_match.get());
            uint8_t* endlfc = reinterpret_cast<uint8_t*>(
                reinterpret_cast<uintptr_t>(startlfc) + 0x150
            );
            
            const auto lfc_instructionList = *Dissassembler.Dissassemble(startlfc, endlfc, true);

            //c->stacksize is copied over from the proto, followed by the zeroing of preload
            log_search("movzx ecx, byte ptr [... + 0x??]");
            const auto maxstackszIns = lfc_instructionList.GetAllInstructionsWhichMatch("movzx", "ecx, byte ptr [", true)[1];
            const auto regUsed = maxstackszIns->detail[0]->reg;

            auto pos = lfc_instructionList.GetInstructionPosition(*maxstackszIns);
            const AsmInstruction* stackszIns = nullptr;

            for (auto it = pos; it != lfc_instructionList.end() && it != pos + 10; ++it) {
                if (it->detail.size() >= 2 && it->detail[1]->reg != X86_REG_INVALID && it->mnemonic == "mov") {
                    stackszIns = &(*it);
                    break;
                }
            }

            LUDUMP_ASSERT(stackszIns != nullptr, "failed to get stacksize instruction");
            const auto stackszOffset = stackszIns->detail[0]->disp;
            log_offset(ClosureFieldToString(ClosureField::stacksize), stackszOffset);
            this->offsets.emplace_back(ClosureField::stacksize, stackszOffset);

            //the very next mov of 0x00 should be preload.
            log_search("mov byte ptr [... + 0x??], 0x0");
            const AsmInstruction* preloadIns = nullptr;
            for (auto it = lfc_instructionList.GetInstructionPosition(*stackszIns); it != lfc_instructionList.end(); ++it) {
                if (it->detail.size() >= 2 && it->detail[1]->imm == 0x00 && it->mnemonic == "mov") {
                    preloadIns = &(*it);
                    break;
                }
            }

            LUDUMP_ASSERT(preloadIns != nullptr, "failed to get preload instruction");
            const auto preloadOffset = preloadIns->detail[0]->disp;
            log_offset(ClosureFieldToString(ClosureField::preload), preloadOffset);
            this->offsets.emplace_back(ClosureField::preload, preloadOffset);


            //finally, we can analyse l.p and uprefs.
            puts("analysing l union...");

            log_search("mov qword ptr [rax + 0x??], ...");
            const AsmInstruction* protoIns = lfc_instructionList.GetAllInstructionsWhichMatch("mov", "qword ptr [rax +", true)[1];
            const auto protoOffset_fromBase = protoIns->detail[0]->disp;
            const auto protoOffset_fromUnion = protoOffset_fromBase - this->unionData.unionOffset;
            log_offset(LUnionFieldToString(l_unionField::p), protoOffset_fromUnion);
            this->unionData.lClosureFields.emplace_back(l_unionField::p, protoOffset_fromUnion);

            const auto uprefIns = lfc_instructionList.GetInstructionWhichMatches("add", "rax, 0x2c", false);
            const auto uprefOffset_fromBase = uprefIns->detail[1]->imm;
            const auto uprefOffset_fromUnion = uprefOffset_fromBase - this->unionData.unionOffset;
            log_offset(LUnionFieldToString(l_unionField::uprefs), uprefOffset_fromUnion);
            this->unionData.lClosureFields.emplace_back(l_unionField::uprefs, uprefOffset_fromUnion);


            //calculate gclist after union
            puts("Calculating offset: \"gclist\"...");
            std::set<ptrdiff_t> occupied{};
            for (const auto& [_key, offset]: this->offsets) occupied.insert(offset);

            //prefer next pointer slot after union
            ptrdiff_t gclistOffset = this->unionData.unionOffset + 0x08;
            if (occupied.count(gclistOffset)) {
                //fallback: first free pointer slot among common positions
                constexpr ptrdiff_t slots[] = {0x10, 0x18, 0x20, 0x28};
                gclistOffset = 0;
                for (const auto s: slots) { if (!occupied.count(s)) {gclistOffset = s; break;}}
            }

            LUDUMP_ASSERT(gclistOffset != 0, "failed to calculate gclist offset");
            log_offset(ClosureFieldToString(ClosureField::gclist), gclistOffset);
            this->offsets.emplace_back(ClosureField::gclist, gclistOffset);
        }
    }

    log_finish("Closure");
}

const std::string ClosureDumper::CUnionToHeader() {
    static const std::unordered_map<c_unionField, const char*> typesMap = {
        {c_unionField::f, "lua_CFunction"},
        {c_unionField::cont, "lua_Continuation"},
        {c_unionField::debugname, "const char*"},
        {c_unionField::upvals, decl_array("TValue", "1")}
    };

    std::sort(this->unionData.cClosureFields.begin(), this->unionData.cClosureFields.end(), [](auto& a, auto& b) -> bool {
        return a.second < b.second;
    });

    std::ostringstream buf {};
    buf << TAB_INDENT << TAB_INDENT << "struct {\n";

    for (const auto& [key, offset]: this->unionData.cClosureFields) {
        const char* type = typesMap.at(key);
        buf << TAB_INDENT << TAB_INDENT << TAB_INDENT;

        if (strstr(type, "ARR") != nullptr)
            buf << parse_decl_array(type, CUnionFieldToString(key));
        else
            buf << type << " " << CUnionFieldToString(key);
        
        buf << ";" << "  //+0x" << std::hex << offset << NEWLINE;
    }

    buf << TAB_INDENT << TAB_INDENT << "} c;";
    return buf.str();
}

const std::string ClosureDumper::LUnionToHeader() {
    static const std::unordered_map<l_unionField, const char*> typesMap = {
        {l_unionField::p, "Proto*"},
        {l_unionField::uprefs, decl_array("TValue", "1")}
    };

    std::sort(this->unionData.lClosureFields.begin(), this->unionData.lClosureFields.end(), [](auto& a, auto& b) -> bool {
        return a.second < b.second;
    });

    std::ostringstream buf {};
    buf << TAB_INDENT << TAB_INDENT << "struct {\n";

    for (const auto& [key, offset]: this->unionData.lClosureFields) {
        const char* type = typesMap.at(key);
        buf << TAB_INDENT << TAB_INDENT << TAB_INDENT;

        if (strstr(type, "ARR") != nullptr)
            buf << parse_decl_array(type, LUnionFieldToString(key));
        else
            buf << type << " " << LUnionFieldToString(key);
        
        buf << ";" << "  //+0x" << std::hex << offset << NEWLINE;
    }

    buf << TAB_INDENT << TAB_INDENT << "} l;";
    return buf.str();
}

std::string ClosureDumper::ToHeaderContents() {
    static const std::unordered_map<ClosureField, const char*> typesMap = {
        {ClosureField::env, "LuaTable*"},
        {ClosureField::gclist, "GCObject*"},
        {ClosureField::isC, "uint8_t"},
        {ClosureField::marked, "uint8_t"},
        {ClosureField::memcat, "uint8_t"},
        {ClosureField::nupvalues, "uint8_t"},
        {ClosureField::preload, "uint8_t"},
        {ClosureField::stacksize, "uint8_t"},
        {ClosureField::tt, "uint8_t"}
    };

    std::sort(this->offsets.begin(), this->offsets.end(), [](auto& a, auto& b) -> bool { return a.second < b.second; });

    bool unionInserted = false;
    std::array<ClosureField, 10> sortedKeys{};
    int outIndex = 0;

    for (int i = 0; i < this->offsets.size(); ++i) {
        auto& [field, offset] = this->offsets[i];
        if (!unionInserted && offset >= this->unionData.unionOffset) {
            sortedKeys[outIndex++] = ClosureField::__union;
            unionInserted = true;
        }
        sortedKeys[outIndex++] = field;
    }

    if (!unionInserted) sortedKeys[outIndex++] = ClosureField::__union;

    //building struct.
    std::ostringstream buf{};
    buf << "struct Closure {" << NEWLINE;

    int offsetIndex = 0;
    for (int i = 0; i < outIndex; ++i) {
        const auto key = sortedKeys[i];

        if (key == ClosureField::__union) {
            buf << TAB_INDENT "union {" << NEWLINE
                << this->CUnionToHeader() << NEWLINE
                << this->LUnionToHeader() << NEWLINE
                << TAB_INDENT "};" << NEWLINE;
            continue;
        }

        const char* type = typesMap.at(key);
        const ptrdiff_t offset = this->offsets[offsetIndex].second;

        buf << TAB_INDENT;
        if (strstr(type, "ARR") != nullptr)
            buf << parse_decl_array(type, ClosureFieldToString(key));
        else
            buf << type << " " << ClosureFieldToString(key);

        buf << ";" << "  //+0x" << std::hex << offset << NEWLINE;

        ++offsetIndex;
    }

    buf << "};";
    return buf.str();
}