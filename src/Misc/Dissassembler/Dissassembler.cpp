/*
This file is a part of the LuGo executor and is licensed under the 
GNU Affero General Public License v3.0.

This file was created for the LuGo executor by 12345koip.
See LICENSE and README for details.
*/


#include "Dissassembler.hpp"
#include <format>
#include <Windows.h>
using namespace LuDumper::Dissassembler;


static bool MatchWithWildcards(std::string_view text, std::string_view pattern) {
    size_t i = 0, j = 0;

    while (i < text.size() && j < pattern.size()) {
        //skip whitespace
        while (i < text.size() && static_cast<uint8_t>(text[i]) <= ' ') ++i;
        while (j < pattern.size() && static_cast<uint8_t>(pattern[j]) <= ' ') ++j;

        if (j + 1 < pattern.size() && pattern[j] == '?' && pattern[j + 1] == '?') {
            //wildcard for two hex chars
            if (i + 1 >= text.size())
                return false;
            else if (!std::isxdigit(static_cast<unsigned char>(text[i])) || !std::isxdigit(static_cast<unsigned char>(text[i + 1])))
                return false;

            i += 2;
            j += 2;
            continue;
        }

        if (pattern[j] == '?') {
            ++i;
            ++j;
            continue;
        }

        //case-insensitive literal match
        uint8_t a = text[i], b = pattern[j];
        if ((a | 0x20) != (b | 0x20)) return false;

        ++i;
        ++j;
    }

    // skip trailing whitespace
    while (i < text.size() && static_cast<unsigned char>(text[i]) <= ' ') ++i;
    while (j < pattern.size() && static_cast<unsigned char>(pattern[j]) <= ' ') ++j;

    return i == text.size() && j == pattern.size();
}


bool InstructionList::HasInstruction(const std::string_view& mnemonic, const std::string_view& operandPattern, bool fuzzy) const {
    for (const AsmInstruction& instruction: this->instructions) {
        if (instruction.mnemonic != mnemonic) continue;
        bool isValid = fuzzy? (instruction.operands.find(operandPattern) != std::string::npos): MatchWithWildcards(instruction.operands, operandPattern);
    
        if (isValid) return true;
    }

    return false;
}

std::vector<const AsmInstruction*> InstructionList::GetAllInstructionsWhichMatch(const std::string_view& mnemonic, const std::string_view& operandPattern, bool fuzzy) const {
    std::vector<const AsmInstruction*> results;

    for (const AsmInstruction& instruction: this->instructions) {
        if (instruction.mnemonic != mnemonic) continue;
        bool valid = fuzzy? (instruction.operands.find(operandPattern) != std::string::npos): MatchWithWildcards(instruction.operands, operandPattern);

        if (valid) results.push_back(&instruction);
    }

    return results;
};

const AsmInstruction* InstructionList::GetInstructionWhichMatches(const std::string_view& mnemonic, const std::string_view& operandPattern, bool fuzzy) const {
    for (const AsmInstruction& instruction: this->instructions) {
        if (instruction.mnemonic != mnemonic) continue;
        bool valid = fuzzy? (instruction.operands.find(operandPattern) != std::string::npos):
            MatchWithWildcards(instruction.operands, operandPattern);
        
        if (valid) return &instruction;
    }

    return nullptr;
}

std::vector<LuDumper::Dissassembler::AsmInstruction>::const_iterator InstructionList::GetInstructionPosition(const std::string_view& mnemonic, const std::string_view& operandPattern, bool fuzzy) const {
    for (auto it = this->instructions.begin(); it != this->instructions.end(); ++it) {
        if (it->mnemonic != mnemonic) continue;

        bool valid = fuzzy? (it->operands.find(operandPattern) != std::string::npos):
            MatchWithWildcards(it->operands, operandPattern);
        
        if (valid) return it;
    }

    return this->instructions.end();
}



Dissassembler& Dissassembler::GetSingleton() {
    static Dissassembler singleton;
    return singleton;
}

Dissassembler::Dissassembler() {
    const cs_err code = cs_open(CS_ARCH_X86, CS_MODE_64, &this->handle);
    if (code != CS_ERR_OK) {
        puts("fatal error: initialisation of dissassembler failed");
        abort(); //placeholder.
    }

    cs_option(this->handle, CS_OPT_DETAIL, CS_OPT_ON);
}

Dissassembler::~Dissassembler() {
    cs_close(&this->handle);
}

void Dissassembler::ForEach(const uint8_t* start, const uint8_t* end, const std::function<void(AsmInstruction&)>& callback) const {
    const uint64_t sizeTotal = static_cast<uint64_t>(end - start); //how big is the chunk?
    const uint8_t* codePtr = start; //where's the code?
    uint64_t remaining = sizeTotal; //how much left?
    uintptr_t address = reinterpret_cast<uintptr_t>(codePtr); //current access address?
    
    cs_insn* insn = cs_malloc(this->handle);
    while (cs_disasm_iter(this->handle, &codePtr, &remaining, &address, insn)) {
        std::vector<uint8_t> bytes (insn->size);
        memcpy(bytes.data(), insn->bytes, insn->size);

        std::vector<std::shared_ptr<CsOperand>> ops;
        if (insn->detail) {
            for (int j = 0; j < insn->detail->x86.op_count; ++j) {
                const cs_x86_op& op = insn->detail->x86.operands[j];
                auto operand = std::make_shared<CsOperand>();
                operand->type = op.type;
                operand->disp = op.mem.disp;
                operand->reg = op.reg;
                operand->imm = op.imm;
                ops.push_back(std::move(operand));
            }
        }

        AsmInstruction wrappedInstruction (insn->mnemonic, insn->op_str, insn->address, insn->size, bytes, std::move(ops), static_cast<x86_insn>(insn->id));
        callback(wrappedInstruction);
    }

    cs_free(insn, 1);
}

std::optional<InstructionList> Dissassembler::Dissassemble(const void* start, const void* end, bool detail) const {
    uintptr_t startAddress = reinterpret_cast<uintptr_t>(start);
    uintptr_t endAddress = reinterpret_cast<uintptr_t>(end);
    uint64_t rawSize = endAddress - startAddress;

    cs_insn* rawIns;
    uint64_t count = cs_disasm(
        this->handle,
        reinterpret_cast<const uint8_t*>(start),
        rawSize,
        startAddress,
        endAddress,
        &rawIns
    );

    if (count == 0) return std::nullopt;
    std::vector<AsmInstruction> decoded;
    
    for (uint64_t i = 0; i < count; ++i) {
        const cs_insn& instruction = rawIns[i];
        std::vector<uint8_t> bytes(instruction.size);
        memcpy(bytes.data(), instruction.bytes, instruction.size);

        std::vector<std::shared_ptr<CsOperand>> ops;
        if (instruction.detail) {
            for (int j = 0; j < instruction.detail->x86.op_count; ++j) {
                const cs_x86_op& op = instruction.detail->x86.operands[j];
                auto operand = std::make_shared<CsOperand>();
                operand->type = op.type;
                operand->disp = op.mem.disp;
                operand->reg = op.reg;
                operand->imm = op.imm;
                ops.push_back(operand);
            }
        }

        decoded.emplace_back(
            instruction.mnemonic,
            instruction.op_str,
            instruction.address,
            instruction.size,
            bytes,
            std::move(ops),
            static_cast<x86_insn>(instruction.id)
        );
    }

    cs_free(rawIns, count);
    return InstructionList(std::move(decoded));
}

static inline bool isMemoryReadable(void* address) {
    MEMORY_BASIC_INFORMATION mbi{};

    if (VirtualQuery(address, &mbi, sizeof(mbi))) {
        DWORD protect = mbi.Protect;

        bool isReadable = (protect & PAGE_READONLY) ||
            (protect & PAGE_READWRITE) ||
            (protect & PAGE_EXECUTE_READ) ||
            (protect & PAGE_EXECUTE_READWRITE);

        return mbi.State == MEM_COMMIT && isReadable;
    }

    return false;
}

void* Dissassembler::GetFunctionStart(void* midFuncInstAddress, void* moduleBase) const {
    uint8_t* ptr = static_cast<uint8_t*>(midFuncInstAddress);

    while (ptr-- && *ptr != INT3 && *(ptr - 1) != INT3) {
        _mm_pause();
    }

    return reinterpret_cast<void*>(ptr);
}

std::optional<void*> Dissassembler::RelativeLeaToRuntimeAddress(const AsmInstruction& insn) const {
    if (insn.mnemonic != "lea") return std::nullopt;

    const auto& dest = insn.detail[0]; //register
    const auto& source = insn.detail[1];

    if (!source) return std::nullopt;
    uintptr_t rip = insn.address + insn.size;
    uintptr_t resolved = rip + source->disp;

    return reinterpret_cast<void*>(resolved);
}

uint8_t* Dissassembler::GetNextRET(uint8_t* address) const {
    while (*address != 0xC3 && *address != 0xCA && *address != 0xC2)
        address++;

    return address;
}