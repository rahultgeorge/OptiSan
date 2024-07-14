# Static Safety and Security Impact Analyses
The static analyses consists of 
1. The value range analysis, from Dataguard,  to identify the spatial unsafe ptr arithmetic operations and the corresponding unsafe objects
2. Static analysis to identify the unsafe memory accesses using the VR results
3. Usable Target analysis which computes a PDG and uses point's to analysis (SVF)


## Usage

The analyses are performed on the LLVM IR bitcode. 

<mark style="background-color: lightblue">
// Performs value range analysis <br>
opt -load ./SecurityImpactAnalysis/ValeRangeAnalysis/libNescheck.so -nescheck program_name.bc -o /dev/null <br>
// Identify and save unsafe operations using VR results <br>
opt -load ./SecurityImpactAnalysis/libUnsafeMemoryOperationsAnalysis.so -compute-actions program_name.bc -o /dev/null <br>
// Compute usable targets<br>
opt -load ./SecurityImpactAnalysis/libUsableTargetAnalysis.so -compute-usable-targets program_name.bc -o /dev/null <br>
</mark>

## References
1. [VR Source- Dataguard NDSS](https://github.com/Lightninghkm/DataGuard)
2. [PDG Source - Program Mandering CCS ](https://github.com/ARISTODE/program-dependence-graph)
3. [SVF Source](https://github.com/SVF-tools/SVF)
4. [LLVM ASAN](https://github.com/llvm-mirror/llvm/blob/master/lib/Transforms/Instrumentation/AddressSanitizer.cpp)


