#include <map>
#include <set>
#include <vector>
#include <cstdio>

#include "llvm/Pass.h"
#include "llvm/ADT/APInt.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/IR/Dominators.h"
#include "llvm/ADT/StringMap.h"

#include "Util.h"

using namespace llvm;
using std::map;
using std::set;
using std::vector;

/**
 * Smart Monitor
 *  This pass instruments GEPS and memset instructions
 *  First optimization - decides which GEPS and memsets to instrument
 *  Second optimization - avoids table lookup in case of globals and
 */

//I switched this to a function pass

namespace {
    struct BaggyBoundsPointersOpt : public FunctionPass {
        static char ID;

        BaggyBoundsPointersOpt() : FunctionPass(ID) {}

        Constant *baggyBoundsTable;
        Function *slowPathFunc;
        Function *getSlotIDFunc;

        DominatorTree *DT;
        DataLayout *DL;

        // map from global variables to their sizes (in bytes)
        map<Value *, int> globalVarSizes;

        BasicBlock *instrumentMemset(BasicBlock *orig, MemSetInst *i, Value *sizeValue) {
            BasicBlock *baggyBlock = BasicBlock::Create(orig->getContext(), "baggy.check",
                                                        orig->getParent(), orig);
            IRBuilder<> builder(baggyBlock);

            Value *Base = i->getDest();
            Value *Length = i->getLength();
            Value *LengthSized;
            if (Length->getType()->getPrimitiveSizeInBits() > 64) {
                LengthSized = builder.CreateTrunc(Length, Type::getInt64Ty(baggyBlock->getContext()));
            } else {
                LengthSized = builder.CreateZExtOrBitCast(Length, Type::getInt64Ty(baggyBlock->getContext()));
            }
            Value *BaseInt = builder.CreatePtrToInt(Base, Type::getInt64Ty(baggyBlock->getContext()));
            Value *EndInt = builder.CreateAdd(BaseInt, LengthSized);
            /*
            Value *TableOffset = builder.CreateLShr(BaseInt, 4, "baggy.offset");
            LoadInst *SizeTablePtr = builder.CreateLoad(sizeTable, "baggy.table");
            Value *Tableaddr = builder.CreateInBoundsGEP(SizeTablePtr, TableOffset);
            LoadInst *Size = builder.CreateLoad(Tableaddr, "alloc.size");
            */
            Value *MaskedSize = builder.CreateZExtOrBitCast(sizeValue, Type::getInt64Ty(baggyBlock->getContext()));
            Value *SizeInt = builder.CreateAnd(MaskedSize, 0x1F);
            Value *Xor = builder.CreateXor(BaseInt, EndInt);
            Value *Result = builder.CreateAShr(Xor, SizeInt);

            // Add the memset instruction to this block
            baggyBlock->getInstList().push_back(i);

            // Create the slowpath block
            BasicBlock *slowPathBlock = BasicBlock::Create(baggyBlock->getContext(), "baggy.slowPath",
                                                           baggyBlock->getParent(), orig);
            IRBuilder<> slowPathBuilder(slowPathBlock);
            Value *slowPathBr, *bufcast, *pcast, *retptr;

            bufcast = slowPathBuilder.CreatePointerCast(Base, Type::getInt64PtrTy(baggyBlock->getContext()));
            pcast = slowPathBuilder.CreateIntToPtr(EndInt, Type::getInt64PtrTy(baggyBlock->getContext()));
            std::vector<llvm::Value *> slowPathFuncArgs;
            slowPathFuncArgs.push_back(bufcast);
            slowPathFuncArgs.push_back(pcast);
            retptr = slowPathBuilder.CreateCall(slowPathFunc, slowPathFuncArgs);
            slowPathBr = slowPathBuilder.CreateBr(orig);


            // Branch to slowpath if necessary
            MDBuilder weightBuilder(baggyBlock->getContext());
            MDNode *branchWeights;
            Value *baggyCheck, *baggyBr;
            baggyCheck = builder.CreateICmpEQ(Result,
                                              ConstantInt::get(IntegerType::get(baggyBlock->getContext(), 64), 0));
            branchWeights = weightBuilder.createBranchWeights(99, 1);
            baggyBr = builder.CreateCondBr(baggyCheck, orig, slowPathBlock, branchWeights);

            return baggyBlock;
        }

        /**
         *
         * @param orig - baggy.split block which now contains the GEP operation
         * @param i  - GEP instruction corresponding to pointer arithmetic
         * @param phi
         * @param sizeValue - For arguments (escaped objects) this is read from the table otherwise for stack and
         * @return
         */
        BasicBlock *instrumentGEP(BasicBlock *orig, GetElementPtrInst *i, PHINode *phi,
                                  Value *sizeValue) {
            BasicBlock *baggyBlock = BasicBlock::Create(orig->getContext(), "baggy.check",
                                                        orig->getParent(), orig);
            IRBuilder<> builder(baggyBlock);
            Value *tmpsize, *sizeint, *baseint, *base;

            // Baggy lookup

            base = builder.CreateConstInBoundsGEP1_64(i->getResultElementType(), i->getOperand(0), 0, "baggy.base");
            baseint = builder.CreatePtrToInt(base, IntegerType::get(baggyBlock->getContext(), 64));
            tmpsize = builder.CreateZExtOrBitCast(sizeValue, IntegerType::get(baggyBlock->getContext(), 64));
            //TODO - For log_z(size) this limits it to 2^31 for a 32 bit system. What about the case when the object size is not saved in the table
            sizeint = builder.CreateAnd(tmpsize, 0x3F);

            // insert arithmetic
            baggyBlock->getInstList().push_back(i);

            // baggy check
            Value *combine, *instint, *result;

            instint = builder.CreatePtrToInt(i, IntegerType::get(baggyBlock->getContext(), 64));
            combine = builder.CreateXor(baseint, instint);
            result = builder.CreateAShr(combine, sizeint, "baggy.result");

            // Create the slowpath block
            BasicBlock *slowPathBlock = BasicBlock::Create(baggyBlock->getContext(), "baggy.slowPath",
                                                           baggyBlock->getParent(), orig);
            IRBuilder<> slowPathBuilder(slowPathBlock);
            Value *slowPathBr, *slowPathPtr, *bufcast, *pcast, *retptr;

            bufcast = slowPathBuilder.CreatePointerCast(base, Type::getInt64PtrTy(baggyBlock->getContext()));
            pcast = slowPathBuilder.CreatePointerCast(i, Type::getInt64PtrTy(baggyBlock->getContext()));
            std::vector<llvm::Value *> slowPathFuncArgs;
            slowPathFuncArgs.push_back(bufcast);
            slowPathFuncArgs.push_back(pcast);
            retptr = slowPathBuilder.CreateCall(slowPathFunc, slowPathFuncArgs);
            slowPathPtr = slowPathBuilder.CreatePointerCast(retptr, i->getType());
            slowPathBr = slowPathBuilder.CreateBr(orig);


            // Branch to slowpath if necessary
            MDBuilder weightBuilder(baggyBlock->getContext());
            MDNode *branchWeights;
            Value *baggyCheck, *baggyBr;
            baggyCheck = builder.CreateICmpEQ(result,
                                              ConstantInt::get(IntegerType::get(baggyBlock->getContext(), 64), 0));
            branchWeights = weightBuilder.createBranchWeights(99, 1);
            baggyBr = builder.CreateCondBr(baggyCheck, orig, slowPathBlock, branchWeights);

            // Add both branches to phi node
            phi->addIncoming(i, baggyBlock);
            phi->addIncoming(slowPathPtr, slowPathBlock);

            return baggyBlock;
        }

        Value *castToIntAndClearTopBit(LLVMContext &ctxt,
                                       BasicBlock::InstListType &iList,
                                       BasicBlock::InstListType::iterator &i,
                                       Value *val) {
            Instruction *toIntInst = new PtrToIntInst(val, IntegerType::get(ctxt, 64));
            // ANDS with a 2^31-1(0x7fffffff) now and with 2^63-1 (0x7fffffffffffffff) 0x7FFFFFFFFFFFFFFF
            Instruction *zeroBitInst = BinaryOperator::Create(Instruction::And, toIntInst,
                                                              ConstantInt::get(IntegerType::get(ctxt, 64),
                                                                               0x7FFFFFFFFFFFFFFF));
            iList.insert(i, toIntInst);
            iList.insert(i, zeroBitInst);
            return zeroBitInst;
        }

        bool doInitialization(Module &M) {
            baggyBoundsTable = M.getOrInsertGlobal("baggy_size_table", Type::getInt8PtrTy(M.getContext()));
            slowPathFunc = M.getFunction("baggy_slowpath");
            if (!slowPathFunc) {
                std::vector<Type *> slowPathFuncArgs;
                slowPathFuncArgs.push_back(Type::getInt64PtrTy(M.getContext()));
                slowPathFuncArgs.push_back(Type::getInt64PtrTy(M.getContext()));

                FunctionType *slowPathFuncType = FunctionType::get(Type::getInt64PtrTy(M.getContext()),
                                                                   slowPathFuncArgs, false);

                slowPathFunc = dyn_cast<Function>(
                        M.getOrInsertFunction("baggy_slowpath", slowPathFuncType).getCallee());
            }

            // Get the get_slot_id function (new indexing scheme)
            getSlotIDFunc = M.getFunction("get_slot_id");
            if (!getSlotIDFunc) {
                std::vector<Type *> getSlotIDArgs;
                getSlotIDArgs.push_back(IntegerType::get(M.getContext(), 64));
                FunctionType *getSlotIDFunctionType = FunctionType::get(
                        /*Result=*/Type::getInt32Ty(M.getContext()),
                        /*Params=*/getSlotIDArgs,
                        /*isVarArg=*/false);

                getSlotIDFunc = Function::Create(getSlotIDFunctionType, GlobalValue::ExternalLinkage, "get_slot_id",
                                                 &M);
            }

            DL = const_cast<DataLayout *>(&(M.getDataLayout()));


            for (Module::global_iterator globalVar = M.global_begin();
                 globalVar != M.global_end(); ++globalVar) {
                globalVarSizes[dyn_cast<Value>(globalVar)] = DL->getTypeAllocSize(
                        globalVar->getType()->getElementType());
            }

        }

        // To deal with preceding blocks
        void getPointerSizesBasicBlock(DomTreeNode *N, Value *SizeTablePtr, map<Value *, Value *> &ptrToSize,
                                       set<Value *> &ignorePtrs, BasicBlock::InstListType::iterator startIter) {
            BasicBlock *BB = N->getBlock();

            BasicBlock::InstListType &instList = BB->getInstList();

            for (BasicBlock::InstListType::iterator inst = startIter;
                 inst != instList.end(); ++inst) {
                if (inst->getType()->isPointerTy()) {
                    switch (inst->getOpcode()) {
                        case Instruction::GetElementPtr:
                            ptrToSize[dyn_cast<Value>(inst)] = ptrToSize[inst->getOperand(0)];
                            break;
                        case Instruction::PHI: {
                            PHINode *phi = cast<PHINode>(inst);
                            PHINode *new_phi = PHINode::Create(IntegerType::get(BB->getContext(), 64),
                                                               phi->getNumIncomingValues());
                            instList.insert(inst, new_phi);
                            ptrToSize[phi] = new_phi;
                            // Due to cyclicity (i.e., a phi node is not dominated by the definitions of
                            // all of its arguments) we need to create everything ptrToSize before we
                            // can insert values into the newly created phi node new_phi. We will do this
                            // at the end.

                            break;
                        }
                        case Instruction::Alloca: {
                            unsigned int allocation_size = DL->getTypeAllocSize(
                                    cast<AllocaInst>(inst)->getType()->getElementType());
                            unsigned int allocation_size_log = get_lg(get_alignment(allocation_size));
                            ptrToSize[dyn_cast<Value>(inst)] = ConstantInt::get(IntegerType::get(BB->getContext(), 64),
                                                                                allocation_size_log);
                            break;
                        }
                        case Instruction::BitCast: {
                            Value *operand = inst->getOperand(0);
                            if (operand->getType()->isPointerTy()) {
                                ptrToSize[dyn_cast<Value>(inst)] = ptrToSize[operand];
                                break;
                            }
                            // else spill over into default
                        }

                            // TODO any more to add? maybe a malloc or realloc call?
                        default:

                            Instruction *base = GetElementPtrInst::CreateInBounds(dyn_cast<Value>(inst),
                                                                                  ArrayRef<Value *>(ConstantInt::get(
                                                                                          IntegerType::get(
                                                                                                  BB->getContext(), 64),
                                                                                          0)), "baggy.base");
                            Instruction *baseint = new PtrToIntInst(base, IntegerType::get(BB->getContext(), 64));
//                            Instruction *tableoffset = BinaryOperator::Create(Instruction::LShr, baseint,
//                                                                              ConstantInt::get(
//                                                                                      IntegerType::get(BB->getContext(),
//                                                                                                       64), 4),
//                                                                              "baggy.offset");

                            Instruction *slotID = CallInst::Create(getSlotIDFunc->getFunctionType(), getSlotIDFunc,
                                                                   ArrayRef<Value *>(baseint), "slotID");

                            Instruction *tableaddr = GetElementPtrInst::CreateInBounds(SizeTablePtr, slotID);
                            Instruction *size = new LoadInst(tableaddr->getType(),
                                                             tableaddr,
                                                             "allocLogSize"); //, Twine("alloc.size.", inst->getValueName()->getKey()));
                            ptrToSize[dyn_cast<Value>(inst)] = size;
                            ++inst;
                            instList.insert(inst, base);
                            instList.insert(inst, baseint);
                            instList.insert(inst, slotID);
                            instList.insert(inst, tableaddr);
                            instList.insert(inst, size);
                            --inst;
                            ignorePtrs.insert(tableaddr);
                            ignorePtrs.insert(base);
                            break;
                    }
                }
            }

            // recurse on children
            const std::vector<DomTreeNode *> &Children = N->getChildren();
            for (unsigned i = 0, e = Children.size(); i != e; ++i) {
                getPointerSizesBasicBlock(Children[i], SizeTablePtr, ptrToSize, ignorePtrs,
                                          Children[i]->getBlock()->getInstList().begin());
            }

        }

        void getPointerSizes(Function &F, map<Value *, Value *> &ptrToSize, set<Value *> &ignorePtrs) {
            // Globals
            for (map<Value *, int>::iterator globalVarP = globalVarSizes.begin();
                 globalVarP != globalVarSizes.end(); ++globalVarP) {
                Value *globalVar = globalVarP->first;
                unsigned int allocation_size_log = get_lg(get_alignment(globalVarP->second));
                // Store the log
                ptrToSize[globalVar] = ConstantInt::get(IntegerType::get(F.getContext(), 64), allocation_size_log);
            }

            BasicBlock &entryBlock = F.getEntryBlock();
            BasicBlock::InstListType &instList = entryBlock.getInstList();
            BasicBlock::InstListType::iterator iter = instList.begin();

            // Load the value of baggy_size_table first
            LoadInst *baggyBoundsTablePtr = new LoadInst(baggyBoundsTable->getType(), baggyBoundsTable, "baggy.table");
            instList.insert(iter, baggyBoundsTablePtr);

            // Arguments, place at top of entry block (entry block has no phi nodes)
            auto argumentList = F.args();

            for (auto argument = argumentList.begin();
                 argument != argumentList.end(); ++argument) {
                if (argument->getType()->isPointerTy()) {
                    Instruction *base = GetElementPtrInst::CreateInBounds(argument, ConstantInt::get(
                            IntegerType::get(F.getContext(), 64), 0), "baggy.base");
                    Instruction *baseint = new PtrToIntInst(base, IntegerType::get(F.getContext(), 64));
//                    Instruction *tableoffset = BinaryOperator::Create(Instruction::LShr, baseint, ConstantInt::get(
//                            IntegerType::get(F.getContext(), 64), 4), "baggy.offset");

                    Instruction *slotID = CallInst::Create(getSlotIDFunc->getFunctionType(), getSlotIDFunc,
                                                           ArrayRef<Value *>(baseint), "slotID");
                    Instruction *tableaddr = GetElementPtrInst::CreateInBounds(baggyBoundsTablePtr, slotID);
                    Instruction *size = new LoadInst(tableaddr->getType(),
                                                     tableaddr,
                                                     "allocLogSize"); //, Twine("alloc.size.", argument->getValueName()->getKey()));
                    instList.insert(iter, base);
                    instList.insert(iter, baseint);
                    instList.insert(iter, slotID);
                    instList.insert(iter, tableaddr);
                    instList.insert(iter, size);
                    // This is log of the size
                    ptrToSize[argument] = size;
                    ignorePtrs.insert(base);
                    ignorePtrs.insert(tableaddr);
                }
            }

            // Traverse dominator tree in pre-order so that we see definitions before uses.
            getPointerSizesBasicBlock(DT->getNode(&entryBlock), baggyBoundsTablePtr, ptrToSize, ignorePtrs, iter);

            // Now finish off the phi nodes
            for (map<Value *, Value *>::iterator phi_pair = ptrToSize.begin();
                 phi_pair != ptrToSize.end(); ++phi_pair) {
                if (isa<PHINode>(phi_pair->first)) {
                    PHINode *phi = cast<PHINode>(phi_pair->first);
                    PHINode *new_phi = cast<PHINode>(phi_pair->second);
                    for (PHINode::block_iterator pred_bb = phi->block_begin();
                         pred_bb != phi->block_end(); ++pred_bb) {
                        new_phi->addIncoming(ptrToSize[phi->getIncomingValueForBlock(*pred_bb)], *pred_bb);
                    }
                }
            }

        }

        bool runOnFunction(Function &F) {
            if (F.isIntrinsic() || F.empty())
                return true;

            DT = &getAnalysis<DominatorTreeWrapperPass>(F).getDomTree();

            // To deal with OOB pointers (MSB set) appropriately for ptr to int and inequality comparisons
            for (Function::iterator bb = F.begin(), bbend = F.end(); bb != bbend; ++bb) {
                BasicBlock *block = &(*bb);
                BasicBlock::InstListType &iList = block->getInstList();
                for (BasicBlock::InstListType::iterator i = iList.begin(); i != iList.end(); ++i) {
                    if (isa<PtrToIntInst>(*i)) {
                        PtrToIntInst *ptii = cast<PtrToIntInst>(i);
                        if (ptii->getDestTy()->getPrimitiveSizeInBits() >= 64) {
                            // AND out the most significant bit of newly created int
                            PtrToIntInst *inst1 = cast<PtrToIntInst>(ptii->clone());
                            //For 32 bits they used 0x7fffffff to clear out the MSB
                            BinaryOperator *inst2 = BinaryOperator::Create(Instruction::And, inst1, ConstantInt::get(
                                    IntegerType::get(block->getContext(), 64), 0x7FFFFFFFFFFFFFFF));
                            iList.insert(i, inst1);
                            ReplaceInstWithInst(i->getParent()->getInstList(), i, inst2);
                        }
                    } else if (isa<ICmpInst>(*i)) {
                        ICmpInst *ici = cast<ICmpInst>(i);
                        if (!ici->isEquality()) {
                            Value *operand2 = ici->getOperand(1);
                            ICmpInst *new_ici = cast<ICmpInst>(ici->clone());
                            for (int op_num = 0; op_num < 2; op_num++) {
                                Value *operand = ici->getOperand(op_num);
                                if (operand->getType()->isPointerTy()) {
                                    new_ici->setOperand(op_num, castToIntAndClearTopBit(block->getContext(), iList, i,
                                                                                        operand));
                                }
                            }
                            ReplaceInstWithInst(i->getParent()->getInstList(), i, new_ici);
                        }
                    }
                }
            }

            map<Value *, Value *> ptrToSize;
            set<Value *> ignorePtrs; // any new getelementptr instructions you make should be ignored
            getPointerSizes(F, ptrToSize, ignorePtrs); // fills up ptrToSize map

            for (Function::iterator bb = F.begin(), bbend = F.end(); bb != bbend; ++bb) {
                BasicBlock *block = &(*bb);
                for (BasicBlock::iterator i = block->begin(), e = block->end(); i != e; ++i) {
                    // If it is a GEP instruction we care about
                    if (isa<GetElementPtrInst>(*i) && !cast<GetElementPtrInst>(i)->hasAllZeroIndices()
                        && ignorePtrs.find(&*i) == ignorePtrs.end()) {
                        // get the value now before replacing i
                        Value *sizeValue = ptrToSize[&*i];

                        BasicBlock *after = block->splitBasicBlock(i, "baggy.split");
                        BasicBlock *baggy;
                        PHINode *phi;
                        GetElementPtrInst *inst = cast<GetElementPtrInst>(i->clone());

                        // Remove the getelementptrinst from the old block
                        // i->removeFromParent();
                        phi = PHINode::Create(i->getType(), 2);
                        ReplaceInstWithInst(i->getParent()->getInstList(), i, phi);

                        // Create the instrumentation block
                        baggy = instrumentGEP(after, inst, phi, sizeValue);

                        // Have control flow through the instrumentation block
                        Instruction *term = block->getTerminator();
                        if (term == NULL) {
                            block->getInstList().push_back(BranchInst::Create(baggy));
                        } else {
                            term->setSuccessor(0, baggy);
                        }

                        // Skip the newly created instrumentation basicblock
                        ++bb;

                        // We're done with this block
                        break;
                    } else if (isa<MemSetInst>(*i)) {
                        Value *sizeValue = ptrToSize[&*(i->getOperand(0))];

                        BasicBlock *after = block->splitBasicBlock(i, "baggy.split");
                        BasicBlock *baggy;
                        MemSetInst *inst = cast<MemSetInst>(i);

                        // remove the instruction from this block
                        i->removeFromParent();

                        // Instrument the function
                        baggy = instrumentMemset(after, inst, sizeValue);

                        // Have control flow through the instrumentation block
                        Instruction *term = block->getTerminator();
                        if (term == NULL) {
                            block->getInstList().push_back(BranchInst::Create(baggy));
                        } else {
                            term->setSuccessor(0, baggy);
                        }

                        // Skip the newly created instrumentation basicblock
                        ++bb;

                        // We're done with this block
                        break;
                    }
                }
            }

            return true;
        }

        void getAnalysisUsage(AnalysisUsage &Info) const {
            Info.addRequired<DominatorTreeWrapperPass>();
        }
    };
}

char BaggyBoundsPointersOpt::ID = 0;
static RegisterPass<BaggyBoundsPointersOpt>
        X("baggy-pointers-opt",
          "Baggy Bounds Pointer Instrumentation Pass",
          false,
          false);
