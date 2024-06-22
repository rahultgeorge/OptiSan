# OptiSan: Using Multiple Spatial Error Defenses to Optimize Stack Memory Protection within a Budget </h3><br> 
There are five components each of which includes a README : <br>
1. Security Impact analyses - to compute unsafe operations and usable targets <br>
2. Cost Estimation - to estimate cost of each defense using the execution profile (gcov) <br>
3. MINLP (MATLAB  + Gurobi) solver - to solve the MINLP protection budget problem to compute placement for a desired budget <br>
4. Static Instrumentation pipeline -  to instrument programs as computed<br>
5. Baggy bounds  - an open source LLVM based implementation


