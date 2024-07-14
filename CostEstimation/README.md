# Cost Estimation and Profiling
The cost estimation depends on two things:

<li> The compiler wrapper script <mark style="background-color: grey">my-clang</mark> along with applying patches (in case of ASan a rebuild is necessary to disable heap metadata operations) allows users to disable classes of operations for a defense, such as disabling ASan checks, and profile programs. </li>
<li>  Static LLVM analysis to <br> 
    <ul>
    1. Computes the execution frequency each operation class is performed 
for a defense using the program's execution profile (generated gcov files). <br>  
    2. Parse and save the relevant exection profile information in the db (requires command line option <mark style="background-color: grey">cov</mark>)  </ul>
</li>
<li> These two components can be used to obtain the execution time for a specific operation class along with the frequency of the operation class to compute a cost estimate as described in the paper. </li>
 

## Usage

Compile program with my-clang and use enviroment variables to disable operations as needed and generate the execution profile (gcov). 

<mark style="background-color: lightblue">
export CC=my-clang CXX=my-clang++ <br>
export OPTISAN_COMPILER_STATE="ASanNoChecks" <br>
export OPTISAN_REQ_COVERAGE="true" <br>
make (Appropriate build command) <br>
// Record execution time manually 
./run (Appropriate command to run) <br>
// Computes execution frequency of operation classes (checks, MD) for each defense <br>
opt -load ./CostEstimation/libCostEstimation.so -cov program_name.bc -o /dev/null <br>
// Compute cost estimate using the time and execution frequency
</mark>
