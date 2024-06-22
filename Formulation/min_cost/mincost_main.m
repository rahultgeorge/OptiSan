global node_map
sshd = 0;
uftpd = 0;
libquantum = 0;
libquantum_v1 = 0;
libquantum_v2 = 1;
libquantum_v3 = 1;
if sshd
    n_num = 10160;
    path_num = 90;
    application = "sshd_1/sshd";
    pn_str = num2str(path_num);
    nn_str = num2str(n_num);
    mon_type_num = 4;
elseif uftpd
    n_num = 572;
    path_num = 9;
    application = "uftpd_1/uftpd";
    pn_str = num2str(path_num);
    nn_str = num2str(n_num);
    mon_type_num = 4;
elseif libquantum
    n_num = 121;
    path_num = 20;
    application = "libquantum/libquantum";
    pn_str = num2str(path_num);
    nn_str = num2str(n_num);
    mon_type_num = 2;
elseif libquantum_v1
    n_num = 121;
    path_num = 20;
    application = "462.libquantum_v1/462.libquantum";
    pn_str = num2str(path_num);
    nn_str = num2str(n_num);
    mon_type_num = 2;
elseif libquantum_v2
    n_num = 121;
    path_num = 20;
    application = "462.libquantum_v2/462.libquantum";
    pn_str = num2str(path_num);
    nn_str = num2str(n_num);
    mon_type_num = 2;
elseif libquantum_v3
    n_num = 121;
    path_num = 20;
    application = "462.libquantum_v3/462.libquantum";
    pn_str = num2str(path_num);
    nn_str = num2str(n_num);
    mon_type_num = 2;
else
    n_num = 0;
    path_num = 0;
end
%{
effi_file = "/Users/mzc796/Documents/MATLAB/minlp/dataset/"+application+"_tes_"+pn_str+".txt";
mon_type_file = "/Users/mzc796/Documents/MATLAB/minlp/dataset/"+application+"_monitor_types.txt";
cost_file = "/Users/mzc796/Documents/MATLAB/minlp/dataset/"+application+"_costs.txt";
coverage_file = "/Users/mzc796/Documents/MATLAB/minlp/dataset/"+application+"_coverage.txt";
accuracy_file = "/Users/mzc796/Documents/MATLAB/minlp/dataset/"+application+"_accuracy.txt";
pathweight_file = "/Users/mzc796/Documents/MATLAB/minlp/dataset/"+application+"_tw.txt";
%}
effi_file = "/Users/mzc796/Documents/MATLAB/gurobi/dataset/"+application+"_t"+pn_str+"_n"+nn_str+"_tes.txt";
mon_type_file = "/Users/mzc796/Documents/MATLAB/gurobi/dataset/"+application+"_monitor_types.txt";
cost_file = "/Users/mzc796/Documents/MATLAB/gurobi/dataset/"+application+"_costs.txt";
coverage_file = "/Users/mzc796/Documents/MATLAB/gurobi/dataset/"+application+"_coverage.txt";
accuracy_file = "/Users/mzc796/Documents/MATLAB/gurobi/dataset/"+application+"_accuracy.txt";
pathweight_file = "/Users/mzc796/Documents/MATLAB/gurobi/dataset/"+application+"_tw.txt";
tgroup_file = "/Users/mzc796/Documents/MATLAB/gurobi/dataset/"+application+"_tgroup.txt";

effi_file_preprocessed = "effi_file.txt";
coverage_file_preprocessed = "coverage_file.txt";
node_map = containers.Map('KeyType','double', 'ValueType','double'); %<key:original_id,value:new_id>
node_num = prune_data(effi_file,coverage_file,path_num,n_num,node_map);
[nodelist,node_mon_map]=build_gurobi_sign_tgroup_model(effi_file_preprocessed,coverage_file_preprocessed,cost_file,mon_type_file,accuracy_file,tgroup_file,path_num,node_num,mon_type_num);
solution_num=path_num*node_num*mon_type_num;
result_map = minlp_gurobi('efficient_monitor.lp');
%showmap(result_map);
solution_translated = translate_result(node_map, nodelist,node_mon_map,result_map)
%[solution,cost,result_map]=extract_solution(solution_num,node_map,nodelist,node_mon_map)
%showmap(result_map);
%profit = testify(result_map,accuracy_file,pathweight_file,effi_file_preprocessed,mon_type_file,path_num,node_num,mon_type_num)