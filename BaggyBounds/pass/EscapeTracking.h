#include "llvm/Analysis/CaptureTracking.h"
#include "llvm/IR/Value.h"

bool PointerMayLeave(const llvm::Value *V, bool ReturnCaptures, bool StoreCaptures);

void PointerMayLeave(const llvm::Value *V, llvm::CaptureTracker *Tracker);
