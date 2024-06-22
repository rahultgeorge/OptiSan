% Program name, # of unsafe op and # targets
[application_name,num_unsafe_op,num_targets] = get_input();
n_num = num_unsafe_op;
application = application_name;
tn_str = num2str(num_targets);
nn_str = num2str(n_num);
mon_type_num = 2;
% Initialization 
path_to_data="~/Desktop/SmartMonitor/datasets/";
effi_file = path_to_data+application+"_t"+tn_str+"_n"+nn_str+"_tes.txt";
mon_type_file = path_to_data+application+"_monitor_types.txt";
cost_file =path_to_data+application+"_costs.txt";
coverage_file =path_to_data+application+"_coverage.txt";
pathweight_file =path_to_data+application+"_tw.txt";
accuracy_file =path_to_data+application+"_accuracy.txt";
tgroup_file =path_to_data+application+"_tgroup.txt";
id_file=path_to_data+application+"_ids.txt";
object_file=path_to_data+application+"_object.txt";

%<key:original_id,value:new_id>
unsafe_op_map = containers.Map('KeyType','double', 'ValueType','double'); 
%<key:original_id,value:new_id>
monitoring_points_map = containers.Map('KeyType','double', 'ValueType','double'); 
% execution_time=input("Enter uninstrument program's execution time (E[T])");


% We no longer use this rewritten effi file.
[node_num,num_mp] = prune_data(effi_file,coverage_file,n_num,unsafe_op_map,monitoring_points_map);
% Stop printing everything
echo off;

% Figure out interesting budget range and point to evaluate
cost_fid = fopen(cost_file,'r');

% Mon types unfortunately are disconnected so for now BBC 1, ASAN 2

asan_monitor_cost=realmax('double');
most_expensive_monitor_cost=realmin('double');
mon_type_map = containers.Map('KeyType','double', 'ValueType','double'); 
for i = 1:mon_type_num
    cline = fgetl(cost_fid);
    C = str2double(cline);
    if i==1
        most_expensive_monitor_cost=C;
    end    
    if i==2
        asan_monitor_cost=C;
    end    
    mon_type_map(i) = C; 
end

disp(["ASAN monitor cost :",asan_monitor_cost]);
disp(["Baggy monitor cost :",most_expensive_monitor_cost]);

cov_fid = fopen(coverage_file,'r');
avg_cov=0;
max_cov=0;
num_mp_non_zero_coverage=0;
% Needed to simulate Candea like approach
coverage_map = containers.Map('KeyType','double', 'ValueType','double'); 
for i = 0:num_mp-1
    cline = fgetl(cov_fid);
    cov_num = str2double(cline);
    if cov_num>0
        num_mp_non_zero_coverage=num_mp_non_zero_coverage+1;
    end
    avg_cov=avg_cov+cov_num;
    max_cov=max([cov_num,max_cov]);
    coverage_map(i)=cov_num;
end




check_frequency_values = cell2mat(coverage_map.values);
cov_75=prctile(check_frequency_values,75,"all");
% avg_cov=avg_cov/num_mp_non_zero_coverage;
avg_cov=avg_cov/num_mp;
non_zero_check_frequency_values=check_frequency_values;
non_zero_check_frequency_values (non_zero_check_frequency_values==0) = NaN;
% avg_cov=avg_cov/16;
% avg_cov=median(sort(non_zero_check_frequency_values),'omitnan');

sum_freq_75=0;
total_sum=sum(check_frequency_values);

for i = 1:num_mp
    cov_num = check_frequency_values(i);
    if cov_num<=cov_75
        sum_freq_75=sum_freq_75+cov_num;
    end
end

display(["Coverage found for:",size(coverage_map),num_mp]);
display(["Average coverage :",avg_cov]);
display(["75 percentile frequency:",cov_75]);
display(["Max coverage :",max_cov]);

cov_75=sum_freq_75/(0.75*num_mp_non_zero_coverage);
display(["75 percentile frequency avg:",cov_75]);

display(["Hottest 25 percentile frequency avg:",((total_sum-sum_freq_75)/(0.25*num_mp_non_zero_coverage))]);

target_to_unsafe_operations_map = containers.Map('KeyType','double', 'ValueType','double'); 

% g_fid = fopen(tgroup_file,'r');
% for j = 1:num_targets
%     tline = fgetl(g_fid);
%     % Target - unsafe op 
%     X = str2num(tline);
%     subt_num = size(X,2) - 1;
%     target_to_unsafe_operations_map(j)=subt_num;
% end


% Scale up the costs as needed (Really small values tolerance will become an issue) 
% Desired order of magnitude for constraint RHS (Cost) is 10^3
% desired_order_of_magnitude=10^3
scale_factor=10^double(int8(log10(asan_monitor_cost*avg_cov)));
scale_factor=((10^3)/scale_factor);
asan_monitor_cost=asan_monitor_cost*scale_factor;
most_expensive_monitor_cost=most_expensive_monitor_cost*scale_factor;

disp(["Scaled ASAN monitor cost :",asan_monitor_cost]);
disp(["Scaled Baggy monitor cost :",most_expensive_monitor_cost]);

% Dont forget about coverage so multiple this by coverage 
% Min budget is to approximately use 1 monitor (cheaper one - ASAN) (Greater than actual min)
min_budget=0;
% Max budget is approximately use expensive monitor for all unsafe ops (considering max coverage) (greater than actual needed max)
max_budget = most_expensive_monitor_cost*max_cov*num_unsafe_op;
% Step size is cost to add 1 additional cheaper monitor
step_size = asan_monitor_cost*avg_cov*2;

% Interesting budget (point we use to evaluate actual placement)
% Rationale - lets programmatically decide based on budget (min, minx)
interesting_budget = (step_size+(most_expensive_monitor_cost*avg_cov*num_unsafe_op))/2;
% Ensure we hit the interesting budget case
budget_factor= double(int8(interesting_budget/step_size));
interesting_budget= budget_factor*step_size;


disp(["Max budget:",max_budget]);
disp(["Min budget:",min_budget]);
disp(["Step value:",step_size]);
display(["Scale factor:",scale_factor]);
% disp(["Estimated Interesting budget value:",interesting_budget/scale_factor]);


user_desired_budget=input("Enter budget (s)");
% user_desired_budget=round(user_desired_budget,3);
is_within_desired_budget=0;
while is_within_desired_budget==0
    % Now call the python script
     % Tightly integrate later
    % [status,cmdout]=system(['python3 plug_play_costs.py',' ',application_name]); 
    % pos=strfind(cmdout,'#:'); ;
    % % %  Still not within budget
    % if (isempty(pos)==0)
    %     cmdout=split(cmdout,newline); 
    %     cmdout=cmdout(10);
    %     cmdout=char(cmdout);
    %     pos=strfind(cmdout,'#:');
    %     display(cmdout);
    %     temp_budget=str2double(extractAfter(cmdout,pos+1))
    %     % temp_budget=extractBefore(temp_budget,)
    %     display(temp_budget);
    %     user_desired_budget=temp_budget;        
    %   else
    %     is_within_desired_budget=1;
    %     break;
    % end
    x = [];
    y2 = [];
    ti1 = [];
    ti2 = [];
    ti3 = [];
    ti4 = [];
    unsafe_ops_protected_results=[];
    % Objective value is sum of protection of all targets so just dividing by number of targets 
    normalized_protected_targets=[];
    % Turn off annotating i.e for the instrumentation off for now
    need_to_annotate_nodes=0;
    changed_step_size=0;
    prev_ojective=0;
    i = min_budget;
    % Set to lesser than AVG so a budget where we cannot cover all if freq is same
    % budge_to_eval=asan_monitor_cost*avg_cov*num_unsafe_op*0.0625;
    % budge_to_eval=0.0025*execution_time*scale_factor;
    budge_to_eval=user_desired_budget*scale_factor;
    asan_objective_value=[];
    baggy_objective_value=[];
    asan_only_unsafe_op_covered=[];
    baggy_only_unsafe_op_covered=[];

    selective_budgets=[budge_to_eval,2*budge_to_eval,4*budge_to_eval,8*budge_to_eval];
    max_budget=15*budge_to_eval;

    % k = 1;
    % for k = 1 : length(selective_budgets)
    % budget = selective_budgets(k);
    budget = budge_to_eval;

    while budget<=max_budget
        budget_as_perc=(budget/scale_factor);
        % budget_as_perc=(budget/scale_factor)*100;
        % budget_as_perc=(budget_as_perc/execution_time);
        x = [x;budget_as_perc];
        [nodeList, node_montype_map, mpList, mp_to_montype_map, node_to_mp_map] = build_gurobi_sign_tgroup_budgeted_model(effi_file,coverage_file,cost_file,pathweight_file,mon_type_file,accuracy_file,tgroup_file,node_num,num_mp,mon_type_num,budget,num_targets,scale_factor,0,object_file,application_name);
        [objective_int, result_map] = minlp_gurobi(char(application_name+"_sign_budgeted_efficient_monitor.lp"));

        solution_translated = translate_result(nodeList,node_montype_map,mpList,mp_to_montype_map,node_to_mp_map,result_map);
        [curr_t1,curr_t2,targets_complete,all_targets_protected,unsafe_ops_protected]=analysis_mon_type(solution_translated);
        unsafe_ops_protected_results=[unsafe_ops_protected_results;(unsafe_ops_protected)];
        ti1=[ti1;(curr_t1)];
        ti2=[ti2;(curr_t2)];
        y2 = [y2;objective_int];
        normalized_protected_targets=[normalized_protected_targets;(objective_int/1)];


        % Budget and targets protected an # ASAN OPs covered
        formulation_results_file = fopen(application_name+"_solver_results.txt",'a+');
        fprintf(formulation_results_file,'%f %f %d %d %d %d\n',budget_as_perc,objective_int,curr_t1,curr_t2,targets_complete, all_targets_protected);
        

        if need_to_annotate_nodes      
            if objective_int==0
                continue
            end
            % Relies on MP
            display(["Placement build budget (s) :",budget_as_perc,asan_only_unsafe_op_covered]);
            place_monitors(solution_translated,application_name);
            need_to_annotate_nodes=0;
            break;
        end  

 
        
        % % ASAN only
        [nodeList, node_montype_map, mpList, mp_to_montype_map, node_to_mp_map] = build_gurobi_sign_tgroup_budgeted_model(effi_file,coverage_file,cost_file,pathweight_file,mon_type_file,accuracy_file,tgroup_file,node_num,num_mp,mon_type_num,budget,num_targets,scale_factor,2,object_file,application_name);
        [objective_int, result_map] = minlp_gurobi(char(application_name+"_sign_budgeted_efficient_monitor_asan.lp"));
        asan_objective_value = [asan_objective_value;(objective_int)];
        solution_translated = translate_result(nodeList,node_montype_map,mpList,mp_to_montype_map,node_to_mp_map,result_map);
        [curr_t1,curr_t2,targets_complete,all_targets_protected,unsafe_ops_protected]=analysis_mon_type(solution_translated);
        asan_only_unsafe_op_covered = [asan_only_unsafe_op_covered;unsafe_ops_protected];
        % Budget and targets protected an # ASAN OPs covered
        formulation_results_file = fopen(application_name+"_asan_solver_results.txt",'a+');
        fprintf(formulation_results_file,'%f %f %d %d %d %d\n',budget_as_perc,objective_int,curr_t1,curr_t2,targets_complete,all_targets_protected);
        
   

        % Baggy only
        [nodeList, node_montype_map, mpList, mp_to_montype_map, node_to_mp_map] = build_gurobi_sign_tgroup_budgeted_model(effi_file,coverage_file,cost_file,pathweight_file,mon_type_file,accuracy_file,tgroup_file,node_num,num_mp,mon_type_num,budget,num_targets,scale_factor,1,object_file,application_name);
        [objective_int, result_map] = minlp_gurobi(char(application_name+"_sign_budgeted_efficient_monitor_baggy.lp"));
        baggy_objective_value = [baggy_objective_value;(objective_int)];
        solution_translated = translate_result(nodeList,node_montype_map,mpList,mp_to_montype_map,node_to_mp_map,result_map);
        [curr_t1,curr_t2,targets_complete,all_targets_protected,unsafe_ops_protected]=analysis_mon_type(solution_translated);
        baggy_only_unsafe_op_covered = [baggy_only_unsafe_op_covered;unsafe_ops_protected];
        % Budget and targets protected an # BBC OPs covered
        formulation_results_file = fopen(application_name+"_baggy_solver_results.txt",'a+');
        fprintf(formulation_results_file,'%f %f %d %d %d %d\n',budget_as_perc,objective_int,curr_t1,curr_t2,targets_complete,all_targets_protected);

        budget=budge_to_eval+budget;
        budget=round(budget,3);

        break;
    end    

    disp("BUDGETS:");
    disp(x)
    % display([" objective value:",y2]);
    disp([" Nrmal objective value:"])
    disp(normalized_protected_targets);
    disp(["Baggy Unsafe OPs covered:"]);
    disp(ti1);
    disp(["ASAN Unsafe OPs covered:"]);
    disp(ti2);
    disp(["Total Unsafe OPs covered:"]);disp(unsafe_ops_protected_results);

    % % Save output to file -we\ll read it later
    % disp(["ASAN Normalized objective value:",asan_objective_value]);
    % % disp(asan_objective_value);
    % disp(["ASAN only Unsafe OPs covered:",asan_only_unsafe_op_covered]);
    % disp(["Baggy Normalized objective value:",baggy_objective_value]);
    % disp(["Baggy only Unsafe OPs covered:",baggy_only_unsafe_op_covered]);

    break;
 
    
   

end    

% display(["ASAN Normalized objective value:"]);
% disp(asan_objective_value);
% display(["ASAN only Unsafe OPs covered:"]);
% disp(asan_only_unsafe_op_covered);
% display(["Baggy Normalized objective value:"]);
% disp(baggy_objective_value);
% display(["Baggy only Unsafe OPs covered:"]);
% disp(baggy_only_unsafe_op_covered);
% disp(curr_t1);





return;

% num_iterations=0;
% interesting_budget=budge_to_eval;
% i=interesting_budget-2*step_size;
% while i<=max_budget
%     budget = i;
%     budget_as_perc=(i/scale_factor)*100;
%     budget_as_perc=(budget_as_perc/execution_time);
%     x = [x;budget_as_perc];
%     % Effi file
%     % [nodeList, node_montype_map, mpList, mp_to_montype_map] = build_gurobi_sign_tgroup_budgeted_model("effi_file.txt",coverage_file,cost_file,pathweight_file,mon_type_file,accuracy_file,tgroup_file,node_num,num_mp,mon_type_num,budget,num_targets,scale_factor,monitoring_points_map);
%     [nodeList, node_montype_map, mpList, mp_to_montype_map] = build_gurobi_sign_tgroup_budgeted_model(effi_file,coverage_file,cost_file,pathweight_file,mon_type_file,accuracy_file,tgroup_file,node_num,num_mp,mon_type_num,budget,num_targets,scale_factor,monitoring_points_map,0);
%     [objective_int, result_map] = minlp_gurobi('sign_budgeted_efficient_monitor.lp');
%     solution_translated = translate_result(nodeList,node_montype_map,mpList,mp_to_montype_map,result_map);
%     [curr_t1,curr_t2,targets_complete,unsafe_ops_protected]=analysis_mon_type(solution_translated);
%     unsafe_ops_protected_results=[unsafe_ops_protected_results;(unsafe_ops_protected/num_unsafe_op)];
%     ti1=[ti1;(curr_t1/num_unsafe_op)];
%     ti2=[ti2;(curr_t2/num_unsafe_op)];
%     y2 = [y2;objective_int];
%     normalized_protected_targets=[normalized_protected_targets;(objective_int/num_targets)];
%     if need_to_annotate_nodes && abs(budget - interesting_budget) < step_size      
%         if objective_int==0
%             interesting_budget=interesting_budget+step_size
%             continue
%         end
%         % Relies on MP
%         display(["Placement build budget:",budget_as_perc]);
%         place_monitors(solution_translated,application_name);
%         need_to_annotate_nodes=0;
%         break;
%     end    

    
%     % display(["Objective int==num_targets:",objective_int,num_targets]);
%     % display(["Objective int==num_targets:",objective_int==num_targets]);
    
%     if uint32(objective_int)==num_targets
%         break;
%         % elseif  objective_int>=(0.8*num_targets)
%         %     break
%     elseif (unsafe_ops_protected>=(0.75*num_unsafe_op)) && (changed_step_size == 0)
%         top_25_avg=((total_sum-sum_freq_75)/(0.25*num_mp_non_zero_coverage));
%         display(["Hottest 25 percentile frequency avg:",top_25_avg]);
%         step_size = asan_monitor_cost*(max_cov/10);
%         display(["Changed Step size",step_size]);
%         changed_step_size = 1;
%     end    
%     prev_ojective=objective_int;
%     i=i+step_size;
%     num_iterations=num_iterations+1;
% end


% Baggy only and ASAN only lines 
% if need_to_run_candea==0
%     j=0;
%     baggy_objective_value=[];
%     % asan_objective_value=[];
%     display(["Baggy only run"]);
%     while j<=num_iterations
%         budget=x(j+1)*(scale_factor/100)*execution_time;
%         % Effi file
%         [nodeList, node_montype_map, mpList, mp_to_montype_map] = build_gurobi_sign_tgroup_budgeted_model(effi_file,coverage_file,cost_file,pathweight_file,mon_type_file,accuracy_file,tgroup_file,node_num,num_mp,mon_type_num,budget,num_targets,scale_factor,monitoring_points_map,1);
%         [objective_int, result_map] = minlp_gurobi('sign_budgeted_efficient_monitor_baggy.lp');
%         baggy_objective_value = [baggy_objective_value;(objective_int/num_targets)];
%         solution_translated = translate_result(nodeList,node_montype_map,mpList,mp_to_montype_map,result_map);
%         [curr_t1,curr_t2,targets_complete,unsafe_ops_protected]=analysis_mon_type(solution_translated);
%         % [nodeList, node_montype_map, mpList, mp_to_montype_map] = build_gurobi_sign_tgroup_budgeted_model(effi_file,coverage_file,cost_file,pathweight_file,mon_type_file,accuracy_file,tgroup_file,node_num,num_mp,mon_type_num,budget,num_targets,scale_factor,monitoring_points_map,2);
%         % [objective_int, result_map] = minlp_gurobi('sign_budgeted_efficient_monitor.lp');
%         % asan_objective_value = [asan_objective_value;(objective_int/num_targets)];
%         display(["Budget int==budget:",x(j+1)*(scale_factor/100)*execution_time,budget]);
%         if uint32(objective_int)==num_targets
%             break;
%         end    
%         j=j+1;
%     end
% end














