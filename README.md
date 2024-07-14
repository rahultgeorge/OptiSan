# OptiSan: Using Multiple Spatial Error Defenses to Optimize Stack Memory Protection within a Budget </h3><br> 
This repository contains the source code for our proposed system <mark style="background-color: grey"> OptiSan </mark>, which has been accepted in the 33rd USENIX Security Symposium (<mark style="background-color: grey"> USENIX Security'24</mark>).
There are five components each of which includes a README : <br>
1. [Security Impact analyses](/SecurityImpactAnalysis/README.md) - to compute unsafe operations and usable targets <br>
2. [Cost Estimation](/CostEstimation/README.md) - to estimate cost of each defense using the execution profile (gcov) <br>
3. [Formulation (MINLP)](/Formulation/README.md) (MATLAB  + Gurobi) solver - to solve the MINLP protection budget problem to compute placement for a desired budget <br>
4. [Static Instrumentation pipeline](/Instrumentation/README.md) -  to instrument programs as computed<br>
5. [Baggy bounds](/BaggyBounds/README.md)  - an open source LLVM based implementation


