/*
This file is a part of the LuGo executor and is licensed under the 
GNU Affero General Public License v3.0.

This file was created for the LuGo executor by 12345koip.
See LICENSE and README for details.

Forked for the LuGo dumper.
*/


#pragma once
#include "Capstone/include/capstone/capstone.h"
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <functional>

#define INT3 0xCC

namespace LuDumper {
    namespace Dissassembler {
        struct CsOperand {
            int type;
            int64_t disp;
            int ref;
            int64_t imm;
            x86_reg reg;
            x86_reg base;
            x86_reg index;
            int scale;
        };

        struct AsmInstruction {
            std::string mnemonic;
            std::string operands;
            uintptr_t address;
            uint64_t size;
            x86_insn id;
            std::vector<uint8_t> bytes;
            std::vector<std::shared_ptr<CsOperand>> detail;
            AsmInstruction(const std::string_view& mn, const std::string_view& op, uintptr_t add, uint64_t sz, std::vector<uint8_t> bytes, std::vector<std::shared_ptr<CsOperand>> detail, x86_insn id):
                mnemonic(mn), operands(op), address(add), size(sz), bytes(std::move(bytes)), detail(std::move(detail)), id(id) {}
            
            bool operator==(const AsmInstruction* other) const noexcept;
        };

        class InstructionList {
            private:
                std::vector<AsmInstruction> instructions;
            
            public:
                bool HasInstruction(const std::string_view& mnemonic, const std::string_view& operandPattern, bool fuzzy = false) const;
                const AsmInstruction* GetInstructionWhichMatches(const std::string_view& mnemonic, const std::string_view& operandPattern, bool fuzzy = false) const;
                std::vector<const AsmInstruction*> GetAllInstructionsWhichMatch(const std::string_view& mnemonic, const std::string_view& operandPattern, bool fuzzy = false) const;
                std::vector<LuDumper::Dissassembler::AsmInstruction>::const_iterator GetInstructionPosition(const std::string_view& mnemonic, const std::string_view& operandPattern, bool fuzzy = false) const;
                std::vector<LuDumper::Dissassembler::AsmInstruction>::const_iterator GetInstructionPosition(const AsmInstruction& ins, bool fuzzy = false) const;

                inline const AsmInstruction* GetInstructionByBytes(const std::vector<uint8_t>& bytes) const {
                    for (const auto& i: this->instructions) {
                        if (i.bytes == bytes)
                            return &i;
                    }

                    return nullptr;
                }


                inline auto begin() const {return this->instructions.begin();}
                inline auto end() const {return this->instructions.end();}
                inline auto rbegin() const {return this->instructions.rbegin();}
                inline auto rend() const {return this->instructions.rend();}

                inline uint64_t size() const {return this->instructions.size();}

                InstructionList(std::vector<AsmInstruction>&& list): instructions(std::move(list)) {}

                InstructionList(const InstructionList&) = delete;
                InstructionList& operator=(const InstructionList&) = delete;
                InstructionList(InstructionList&&) = default;
                InstructionList& operator=(InstructionList&&) = default;

                inline const AsmInstruction& operator[](uint64_t i) const {
                    return this->instructions[i];
                };
        };

        class Dissassembler {
            private:
                csh handle;

            public:
                Dissassembler();
                ~Dissassembler();

                Dissassembler(Dissassembler&) = delete;

                static Dissassembler& GetSingleton();
                std::optional<InstructionList> Dissassemble(const void* start, const void* end, bool detail = false) const;

                void* GetFunctionStart(void* midFuncInstAddress, void* moduleBase) const;
                uint8_t* GetNextRET(uint8_t* address) const;
                void ForEach(const uint8_t* start, const uint8_t* end, const std::function<void(AsmInstruction&)>& callback) const;
                std::optional<void*> RelativeLeaToRuntimeAddress(const AsmInstruction& insn) const;
        };
    }
}