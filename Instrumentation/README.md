# OptiSan Instrumentation


The compiler wrapper script <mark style="background-color: grey">my-clang</mark> allows users to instrument the program as per the computed placement (disabling all relevant operations). Note - To disable ASan heap operations ASan must be rebuilt (refer to patches).  <br>

This requires all the previous steps to be completed and all relevant information to be present in the database.


## Usage

Compile program with my-clang and use enviroment variable OPTISAN_COMPILER_STATE to instrument as per the computed placement.

<mark style="background-color: lightblue">
export CC=my-clang CXX=my-clang++ <br>
export OPTISAN_COMPILER_STATE="PlacementMode" <br>
make (Appropriate build command) <br>
./run (Appropriate command to run) <br>
</mark>
