
## OptiSan Placement Formulation (MINLP) using Matlab - Gurobi solver

The max profit formulation is the formulation presented and evaluated in the paper. The min cost is not currently maintained. <br>

The <mark>maxprofit_main.m</mark> file contains a variable <mark>path_to_data</mark> to identify the relevant program information (files) needed for the formulation. <br>
 The variable <mark>need_to_annotate_nodes</mark> can be used to compute placement for budget, save results (graph database) and exit. The script defaults to 15 iterations starting from budget entered to 15*budget. 


### Usage
<mark style="background-color: lightblue">
// Pre-requisite - generate requried inputs through monitoring_info_driver.py in scripts <br>
python3  monitoring_info_driver.py <br>
// Run matlab <br>
matlab -nodisplay -nosplash -nodesktop <br>
// Run max profile script (maxprofit_main) <br>
run Formulation/max_profit/maxprofit_main.m <br>
// Enter relevant information command line-  <br>
1.  Program name 
2. Number of unsafe operations 
3. Number of usable targets 
4. Budget (seconds) 
</mark>

