#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/ErrorHandling.h"

#include <cstdint>
#include <cstdlib>
#include <random>
#include <string>
#include <vector>

using namespace llvm;

namespace {

enum Opcode : uint8_t {
    OP_BLOCK = 1,
    OP_PHI = 2,
    OP_ADD = 3,
    OP_SUB = 4,
    OP_MUL = 5,
    OP_UDIV = 6,
    OP_SDIV = 7,
    OP_UREM = 8,
    OP_SREM = 9,
    OP_AND = 10,
    OP_OR = 11,
    OP_XOR = 12,
    OP_SHL = 13,
    OP_LSHR = 14,
    OP_ASHR = 15,
    OP_ICMP = 16,
    OP_SELECT = 17,
    OP_TRUNC = 18,
    OP_ZEXT = 19,
    OP_SEXT = 20,
    OP_BR = 21,
    OP_CBR = 22,
    OP_RET = 23,
};

class Bytecode {
  public:
    void u8(uint8_t Value) { Bytes.push_back(Value); }

    void u16(uint16_t Value) {
        u8(static_cast<uint8_t>(Value));
        u8(static_cast<uint8_t>(Value >> 8));
    }

    size_t u32(uint32_t Value) {
        const size_t Position = Bytes.size();
        u16(static_cast<uint16_t>(Value));
        u16(static_cast<uint16_t>(Value >> 16));
        return Position;
    }

    void u64(uint64_t Value) {
        u32(static_cast<uint32_t>(Value));
        u32(static_cast<uint32_t>(Value >> 32));
    }

    void patchU32(size_t Position, uint32_t Value) {
        for (unsigned I = 0; I < 4; ++I) {
            Bytes[Position + I] = static_cast<uint8_t>(Value >> (I * 8));
        }
    }

    size_t size() const { return Bytes.size(); }
    ArrayRef<uint8_t> data() const { return Bytes; }

  private:
    std::vector<uint8_t> Bytes;
};

struct BranchPatch {
    size_t Position;
    const BasicBlock *Target;
};

[[noreturn]] void fail(const Function &F, const Twine &Message) {
    report_fatal_error(Twine("Mocika Native VMP rejected function '") +
                       F.getName() + "': " + Message, false);
}

uint8_t integerWidth(const Function &F, Type *Ty, StringRef Context) {
    auto *Integer = dyn_cast<IntegerType>(Ty);
    if (Integer == nullptr || Integer->getBitWidth() == 0 ||
        Integer->getBitWidth() > 64) {
        fail(F, Twine(Context) + " must be an integer no wider than 64 bits");
    }
    return static_cast<uint8_t>(Integer->getBitWidth());
}

uint64_t hashText(StringRef Text, uint64_t Seed) {
    uint64_t Hash = Seed == 0 ? UINT64_C(1469598103934665603) : Seed;
    for (const unsigned char Byte : Text.bytes()) {
        Hash ^= Byte;
        Hash *= UINT64_C(1099511628211);
    }
    return Hash;
}

uint8_t opcodeKey(const Module &M, const Function &F) {
    uint64_t Seed = 0;
    if (const char *Configured = std::getenv("MOCIKA_VMP_SEED")) {
        Seed = hashText(Configured, 0);
    } else {
        std::random_device Device;
        Seed = (static_cast<uint64_t>(Device()) << 32) ^ Device();
    }
    Seed = hashText(M.getModuleIdentifier(), Seed);
    Seed = hashText(F.getName(), Seed);
    return static_cast<uint8_t>((Seed % 255) + 1);
}

SmallVector<Function *, 8> annotatedFunctions(Module &M) {
    SmallVector<Function *, 8> Result;
    GlobalVariable *Annotations = M.getGlobalVariable("llvm.global.annotations");
    if (Annotations == nullptr || !Annotations->hasInitializer()) {
        return Result;
    }
    auto *Array = dyn_cast<ConstantArray>(Annotations->getInitializer());
    if (Array == nullptr) {
        return Result;
    }
    for (Value *Entry : Array->operands()) {
        auto *Record = dyn_cast<ConstantStruct>(Entry);
        if (Record == nullptr || Record->getNumOperands() < 2) {
            continue;
        }
        auto *F = dyn_cast<Function>(Record->getOperand(0)->stripPointerCasts());
        auto *TextGlobal = dyn_cast<GlobalVariable>(
            Record->getOperand(1)->stripPointerCasts());
        if (F == nullptr || TextGlobal == nullptr || !TextGlobal->hasInitializer()) {
            continue;
        }
        auto *Text = dyn_cast<ConstantDataArray>(TextGlobal->getInitializer());
        if (Text != nullptr && Text->isCString() &&
            Text->getAsCString() == "mocika_vmp") {
            Result.push_back(F);
        }
    }
    return Result;
}

class FunctionEncoder {
  public:
    FunctionEncoder(Module &M, Function &F)
        : M(M), F(F), Key(opcodeKey(M, F)) {}

    std::vector<uint8_t> encode() {
        validateSignature();
        assignIds();
        validateInstructions();

        Code.u8('M');
        Code.u8('V');
        Code.u8('M');
        Code.u8('P');
        Code.u8(1);
        Code.u8(Key);
        Code.u16(static_cast<uint16_t>(Registers.size()));
        Code.u16(static_cast<uint16_t>(F.arg_size()));

        for (BasicBlock &Block : F) {
            BlockOffsets[&Block] = static_cast<uint32_t>(Code.size());
            opcode(OP_BLOCK);
            Code.u16(BlockIds.lookup(&Block));
            for (Instruction &Instruction : Block) {
                if (isa<DbgInfoIntrinsic>(Instruction)) {
                    continue;
                }
                encodeInstruction(Instruction);
            }
        }
        for (const BranchPatch &Patch : Patches) {
            auto Found = BlockOffsets.find(Patch.Target);
            if (Found == BlockOffsets.end()) {
                fail(F, "branch target is outside the selected function");
            }
            Code.patchU32(Patch.Position, Found->second);
        }
        return std::vector<uint8_t>(Code.data().begin(), Code.data().end());
    }

  private:
    Module &M;
    Function &F;
    uint8_t Key;
    Bytecode Code;
    DenseMap<const Value *, uint16_t> Registers;
    DenseMap<const BasicBlock *, uint16_t> BlockIds;
    DenseMap<const BasicBlock *, uint32_t> BlockOffsets;
    SmallVector<BranchPatch, 16> Patches;

    void validateSignature() {
        if (F.isDeclaration() || F.isVarArg()) {
            fail(F, "it must be a defined, non-variadic function");
        }
        integerWidth(F, F.getReturnType(), "return type");
        if (F.arg_size() > UINT16_MAX) {
            fail(F, "too many arguments");
        }
        for (Argument &Argument : F.args()) {
            integerWidth(F, Argument.getType(), "argument type");
        }
    }

    void assignIds() {
        uint32_t NextRegister = 0;
        for (Argument &Argument : F.args()) {
            Registers[&Argument] = checkedRegister(NextRegister++);
        }
        uint32_t NextBlock = 0;
        for (BasicBlock &Block : F) {
            if (NextBlock > UINT16_MAX) {
                fail(F, "too many basic blocks");
            }
            BlockIds[&Block] = static_cast<uint16_t>(NextBlock++);
            for (Instruction &Instruction : Block) {
                if (!Instruction.getType()->isVoidTy() &&
                    !isa<DbgInfoIntrinsic>(Instruction)) {
                    Registers[&Instruction] = checkedRegister(NextRegister++);
                }
            }
        }
        if (Registers.empty()) {
            fail(F, "no VM registers were generated");
        }
    }

    uint16_t checkedRegister(uint32_t Register) {
        if (Register >= 512) {
            fail(F, "requires more than the runtime limit of 512 registers");
        }
        return static_cast<uint16_t>(Register);
    }

    void validateInstructions() {
        for (Instruction &Instruction : instructions(F)) {
            if (isa<DbgInfoIntrinsic>(Instruction)) {
                continue;
            }
            if (auto *Binary = dyn_cast<BinaryOperator>(&Instruction)) {
                if (binaryOpcode(Binary->getOpcode()) == 0) {
                    fail(F, Twine("unsupported binary instruction: ") +
                                Binary->getOpcodeName());
                }
                integerWidth(F, Binary->getType(), "binary result");
                continue;
            }
            if (auto *Compare = dyn_cast<ICmpInst>(&Instruction)) {
                integerWidth(F, Compare->getOperand(0)->getType(),
                             "comparison operand");
                continue;
            }
            if (auto *Select = dyn_cast<SelectInst>(&Instruction)) {
                integerWidth(F, Select->getType(), "select result");
                continue;
            }
            if (auto *Cast = dyn_cast<CastInst>(&Instruction)) {
                if (!isa<TruncInst, ZExtInst, SExtInst>(Cast)) {
                    fail(F, Twine("unsupported cast instruction: ") +
                                Cast->getOpcodeName());
                }
                integerWidth(F, Cast->getSrcTy(), "cast source");
                integerWidth(F, Cast->getDestTy(), "cast destination");
                continue;
            }
            if (auto *Phi = dyn_cast<PHINode>(&Instruction)) {
                integerWidth(F, Phi->getType(), "phi result");
                if (Phi->getNumIncomingValues() == 0 ||
                    Phi->getNumIncomingValues() > UINT16_MAX) {
                    fail(F, "phi incoming count is invalid");
                }
                continue;
            }
            if (auto *Branch = dyn_cast<BranchInst>(&Instruction)) {
                if (Branch->isConditional() &&
                    !Branch->getCondition()->getType()->isIntegerTy(1)) {
                    fail(F, "conditional branch must use an i1 condition");
                }
                continue;
            }
            if (auto *Return = dyn_cast<ReturnInst>(&Instruction)) {
                if (Return->getReturnValue() == nullptr) {
                    fail(F, "void return is unsupported");
                }
                continue;
            }
            fail(F, Twine("unsupported instruction: ") +
                        Instruction.getOpcodeName());
        }
    }

    uint8_t binaryOpcode(unsigned LLVMOpcode) const {
        switch (LLVMOpcode) {
            case Instruction::Add: return OP_ADD;
            case Instruction::Sub: return OP_SUB;
            case Instruction::Mul: return OP_MUL;
            case Instruction::UDiv: return OP_UDIV;
            case Instruction::SDiv: return OP_SDIV;
            case Instruction::URem: return OP_UREM;
            case Instruction::SRem: return OP_SREM;
            case Instruction::And: return OP_AND;
            case Instruction::Or: return OP_OR;
            case Instruction::Xor: return OP_XOR;
            case Instruction::Shl: return OP_SHL;
            case Instruction::LShr: return OP_LSHR;
            case Instruction::AShr: return OP_ASHR;
            default: return 0;
        }
    }

    void opcode(uint8_t Canonical) { Code.u8(Canonical ^ Key); }

    uint16_t reg(const Value *Value) {
        auto Found = Registers.find(Value);
        if (Found == Registers.end()) {
            fail(F, "instruction references an unsupported value");
        }
        return Found->second;
    }

    void value(const Value *Value) {
        if (auto *Integer = dyn_cast<ConstantInt>(Value)) {
            Code.u8(1);
            Code.u64(Integer->getValue().zextOrTrunc(64).getZExtValue());
            return;
        }
        Code.u8(0);
        Code.u16(reg(Value));
    }

    void encodeInstruction(Instruction &Instruction) {
        if (auto *Binary = dyn_cast<BinaryOperator>(&Instruction)) {
            opcode(binaryOpcode(Binary->getOpcode()));
            Code.u16(reg(Binary));
            Code.u8(integerWidth(F, Binary->getType(), "binary result"));
            value(Binary->getOperand(0));
            value(Binary->getOperand(1));
            return;
        }
        if (auto *Compare = dyn_cast<ICmpInst>(&Instruction)) {
            opcode(OP_ICMP);
            Code.u16(reg(Compare));
            Code.u8(integerWidth(F, Compare->getOperand(0)->getType(),
                                 "comparison operand"));
            Code.u8(comparePredicate(Compare->getPredicate()));
            value(Compare->getOperand(0));
            value(Compare->getOperand(1));
            return;
        }
        if (auto *Select = dyn_cast<SelectInst>(&Instruction)) {
            opcode(OP_SELECT);
            Code.u16(reg(Select));
            Code.u8(integerWidth(F, Select->getType(), "select result"));
            value(Select->getCondition());
            value(Select->getTrueValue());
            value(Select->getFalseValue());
            return;
        }
        if (auto *Cast = dyn_cast<CastInst>(&Instruction)) {
            opcode(isa<TruncInst>(Cast) ? OP_TRUNC
                   : isa<ZExtInst>(Cast) ? OP_ZEXT
                                         : OP_SEXT);
            Code.u16(reg(Cast));
            Code.u8(integerWidth(F, Cast->getSrcTy(), "cast source"));
            Code.u8(integerWidth(F, Cast->getDestTy(), "cast destination"));
            value(Cast->getOperand(0));
            return;
        }
        if (auto *Phi = dyn_cast<PHINode>(&Instruction)) {
            opcode(OP_PHI);
            Code.u16(reg(Phi));
            Code.u8(integerWidth(F, Phi->getType(), "phi result"));
            Code.u16(static_cast<uint16_t>(Phi->getNumIncomingValues()));
            for (unsigned I = 0; I < Phi->getNumIncomingValues(); ++I) {
                Code.u16(BlockIds.lookup(Phi->getIncomingBlock(I)));
                value(Phi->getIncomingValue(I));
            }
            return;
        }
        if (auto *Branch = dyn_cast<BranchInst>(&Instruction)) {
            if (Branch->isUnconditional()) {
                opcode(OP_BR);
                Patches.push_back({Code.u32(0), Branch->getSuccessor(0)});
            } else {
                opcode(OP_CBR);
                value(Branch->getCondition());
                Patches.push_back({Code.u32(0), Branch->getSuccessor(0)});
                Patches.push_back({Code.u32(0), Branch->getSuccessor(1)});
            }
            return;
        }
        if (auto *Return = dyn_cast<ReturnInst>(&Instruction)) {
            opcode(OP_RET);
            Code.u8(integerWidth(F, F.getReturnType(), "return type"));
            value(Return->getReturnValue());
            return;
        }
        fail(F, Twine("encoder reached unsupported instruction: ") +
                    Instruction.getOpcodeName());
    }

    uint8_t comparePredicate(CmpInst::Predicate Predicate) {
        switch (Predicate) {
            case CmpInst::ICMP_EQ: return 0;
            case CmpInst::ICMP_NE: return 1;
            case CmpInst::ICMP_UGT: return 2;
            case CmpInst::ICMP_UGE: return 3;
            case CmpInst::ICMP_ULT: return 4;
            case CmpInst::ICMP_ULE: return 5;
            case CmpInst::ICMP_SGT: return 6;
            case CmpInst::ICMP_SGE: return 7;
            case CmpInst::ICMP_SLT: return 8;
            case CmpInst::ICMP_SLE: return 9;
            default: fail(F, "unsupported integer comparison predicate");
        }
    }
};

void replaceWithInterpreter(Module &M, Function &F,
                            ArrayRef<uint8_t> Program) {
    LLVMContext &Context = M.getContext();
    auto *ProgramType = ArrayType::get(Type::getInt8Ty(Context), Program.size());
    auto *Initializer = ConstantDataArray::get(Context, Program);
    auto *ProgramGlobal = new GlobalVariable(
        M, ProgramType, true, GlobalValue::PrivateLinkage, Initializer,
        Twine("__mocika_vmp_program_") + F.getName());
    ProgramGlobal->setSection(M.getTargetTriple().isOSBinFormatMachO()
                                  ? "__DATA,__mocika_vmp"
                                  : ".mocika.vmp");
    ProgramGlobal->setAlignment(Align(1));

    Type *I32 = Type::getInt32Ty(Context);
    Type *I64 = Type::getInt64Ty(Context);
    Type *Pointer = PointerType::getUnqual(Context);
    auto *RuntimeType = FunctionType::get(
        I64, {Pointer, I32, Pointer, I32, Pointer}, false);
    FunctionCallee Runtime = M.getOrInsertFunction("mocika_vmp_exec_i64", RuntimeType);
    FunctionCallee Trap = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::trap);

    F.deleteBody();
    F.removeFnAttr(Attribute::AlwaysInline);
    F.addFnAttr(Attribute::NoInline);
    if (F.hasPersonalityFn()) {
        F.setPersonalityFn(nullptr);
    }

    BasicBlock *Entry = BasicBlock::Create(Context, "mocika.vmp.entry", &F);
    BasicBlock *Success = BasicBlock::Create(Context, "mocika.vmp.return", &F);
    BasicBlock *Failure = BasicBlock::Create(Context, "mocika.vmp.failure", &F);
    IRBuilder<> Builder(Entry);

    const uint64_t StorageCount = std::max<uint64_t>(1, F.arg_size());
    auto *ArgumentsType = ArrayType::get(I64, StorageCount);
    Value *Arguments = Builder.CreateAlloca(ArgumentsType, nullptr, "mocika.vmp.args");
    Value *Zero = ConstantInt::get(I32, 0);
    uint32_t Index = 0;
    for (Argument &Argument : F.args()) {
        Value *Slot = Builder.CreateInBoundsGEP(
            ArgumentsType, Arguments,
            {Zero, ConstantInt::get(I32, Index++)});
        Builder.CreateStore(Builder.CreateZExtOrTrunc(&Argument, I64), Slot);
    }
    Value *ArgumentsPointer = Builder.CreateInBoundsGEP(
        ArgumentsType, Arguments, {Zero, Zero});
    Value *Ok = Builder.CreateAlloca(I32, nullptr, "mocika.vmp.ok");
    Builder.CreateStore(ConstantInt::get(I32, 0), Ok);
    Value *Result = Builder.CreateCall(
        Runtime,
        {ProgramGlobal, ConstantInt::get(I32, Program.size()), ArgumentsPointer,
         ConstantInt::get(I32, F.arg_size()), Ok},
        "mocika.vmp.result");
    Value *Succeeded = Builder.CreateICmpEQ(
        Builder.CreateLoad(I32, Ok), ConstantInt::get(I32, 1));
    Builder.CreateCondBr(Succeeded, Success, Failure);

    Builder.SetInsertPoint(Failure);
    Builder.CreateCall(Trap);
    Builder.CreateUnreachable();

    Builder.SetInsertPoint(Success);
    Builder.CreateRet(Builder.CreateTruncOrBitCast(Result, F.getReturnType()));
}

class MocikaNativeVmpPass : public PassInfoMixin<MocikaNativeVmpPass> {
  public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
        SmallVector<Function *, 8> Functions = annotatedFunctions(M);
        if (Functions.empty()) {
            return PreservedAnalyses::all();
        }
        for (Function *F : Functions) {
            FunctionEncoder Encoder(M, *F);
            const std::vector<uint8_t> Program = Encoder.encode();
            replaceWithInterpreter(M, *F, Program);
        }
        return PreservedAnalyses::none();
    }
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION,
        "MocikaNativeVmpPass",
        "1.0.0",
        [](PassBuilder &Builder) {
            Builder.registerOptimizerLastEPCallback(
                [](ModulePassManager &Manager, OptimizationLevel,
                   ThinOrFullLTOPhase) {
                    Manager.addPass(MocikaNativeVmpPass());
                });
            Builder.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &Manager,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name != "mocika-native-vmp") {
                        return false;
                    }
                    Manager.addPass(MocikaNativeVmpPass());
                    return true;
                });
        },
    };
}
