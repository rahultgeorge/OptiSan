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
%<key:original_id,value:new_id>
unsafe_op_map = containers.Map('KeyType','double', 'ValueType','double'); 
%<key:original_id,value:new_id>
monitoring_points_map = containers.Map('KeyType','double', 'ValueType','double'); 
execution_time=input("Enter uninstrument program's execution time (E[T])");
% We no longer use this rewritten effi file.
[node_num,num_mp] = prune_data(effi_file,coverage_file,n_num,unsafe_op_map,monitoring_points_map);
% Stop printing everything
echo off;

% Figure out interesting budget range and point to evaluate
cost_fid = fopen(cost_file,'r');
cheapest_monitor_cost=realmax('double');
most_expensive_monitor_cost=realmin('double');
mon_type_map = containers.Map('KeyType','double', 'ValueType','double'); 
for i = 1:mon_type_num
    cline = fgetl(cost_fid);
    C = str2double(cline);
    if C<cheapest_monitor_cost
        cheapest_monitor_cost=C;
    end    
    if C>most_expensive_monitor_cost
        most_expensive_monitor_cost=C;
    end    
    mon_type_map(i) = C; 
end

disp(["Cheaper monitor cost :",cheapest_monitor_cost]);
disp(["Expensive monitor cost :",most_expensive_monitor_cost]);

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

need_to_run_candea=0;

if need_to_run_candea==1

    %% To simulate Candea need to read monitoring options info and accuracy info - connect that to freq info
    em_fileID = fopen(effi_file,'r');
    mt_fileID = fopen(mon_type_file,'r');
    asan_unsafe_operation_to_monitoring_points_cost_map = containers.Map('KeyType','double', 'ValueType','double'); 
    unsafe_op_to_max_profit_map = containers.Map('KeyType','double', 'ValueType','double'); 
    op_index = 0;
    while op_index < num_unsafe_op
        %read efficient monitor file
        es_num = textscan(em_fileID,'%d',1,'Delimiter',';');
        % Num of monitor options for unsafe op
        s_num = transpose(es_num{:});
        tline = fgetl(em_fileID);
        % Unsafe operation
        tline = fgetl(em_fileID);
        X = str2num(tline);
        %read monitor type file
        ttline = fgetl(mt_fileID);
        set_index = 0;
        unsafe_op_to_max_profit_map(X(1))=0;
        % display(["UNsafe operation:",X(1)]);
        while ischar(tline) && set_index < s_num
            % Parse mp information (one line per monitor option)
            tline = fgetl(em_fileID);
            Y = str2num(tline);
            %monitor type for the monitoring option
            ttline = fgetl(mt_fileID);
            T = str2num(ttline);
            if T==2
                freq_for_unsafe_op=0;
                for i = 1:size(Y,2)     
                    % display(["MP:",Y(i)]);
                    freq_for_unsafe_op=freq_for_unsafe_op+coverage_map(Y(i));
                end
                asan_unsafe_operation_to_monitoring_points_cost_map(X(1))=freq_for_unsafe_op;
            end
            set_index = set_index + 1;         
        end
        op_index = op_index + 1;
    end
    
    %% Need to calculate objective value as well so
    g_fid = fopen(tgroup_file,'r');
    for j = 0:num_targets-1
        tline = fgetl(g_fid);
        % Target - unsafe op 
        X = str2num(tline);
        subt_num = size(X,2) - 1;
        for i = 1:subt_num
            unsafe_op_to_max_profit_map(X(i))=unsafe_op_to_max_profit_map(X(i))+(1/subt_num);
        end
    end

    disp(["UPA-Max profit computed for :",size(unsafe_op_to_max_profit_map)]);


    %% Need accuracy as well 
    accu_fileID = fopen(accuracy_file,'r');
    accu_map = containers.Map('KeyType','double', 'ValueType','double'); 
    asan_accuracy=0;
    op_index = 0;
    while op_index < 1
        es_num = textscan(accu_fileID,'%d',1,'Delimiter',';');
        % Num of monitoring options
        s_num = transpose(es_num{:});
        aline = fgetl(accu_fileID);
        set_index = 0;
        while ischar(aline) & set_index < s_num
            accu = textscan(accu_fileID,'%f',1,'Delimiter',';');
            accu_value = transpose(accu{:});
            aline = fgetl(accu_fileID);
            if set_index==s_num-1
                asan_accuracy=accu_value;
            end
            set_index = set_index + 1;
        end
        op_index = op_index + 1;
    end


    display(["ASAN accuracy:",asan_accuracy]);
end

check_frequency_values = cell2mat(coverage_map.values);
cov_75=prctile(check_frequency_values,75,"all");
avg_cov=avg_cov/num_mp_non_zero_coverage;
avg_cov=avg_cov/num_mp;
non_zero_check_frequency_values=check_frequency_values;
non_zero_check_frequency_values (non_zero_check_frequency_values==0) = NaN;
avg_cov=median(sort(non_zero_check_frequency_values),'omitnan');

sum_freq_75=0;
total_sum=sum(check_frequency_values);

for i = 1:num_mp
    cov_num = check_frequency_values(i);
    if cov_num<=cov_75
        sum_freq_75=sum_freq_75+cov_num;
    end
end

display(["Coverage found for:",size(coverage_map)]);
display(["Average coverage :",avg_cov]);
display(["75 percentile frequency:",cov_75]);
display(["Max coverage :",max_cov]);

cov_75=sum_freq_75/(0.75*num_mp_non_zero_coverage);
display(["75 percentile frequency avg:",cov_75]);

display(["Hottest 25 percentile frequency avg:",((total_sum-sum_freq_75)/(0.25*num_mp_non_zero_coverage))]);

target_to_unsafe_operations_map = containers.Map('KeyType','double', 'ValueType','double'); 

g_fid = fopen(tgroup_file,'r');
for j = 1:num_targets
    tline = fgetl(g_fid);
    % Target - unsafe op 
    X = str2num(tline);
    subt_num = size(X,2) - 1;
    target_to_unsafe_operations_map(j)=subt_num;
end


% Scale up the costs as needed (Really small values tolerance will become an issue) 
% Desired order of magnitude for constraint RHS (Cost) is 10^3
% desired_order_of_magnitude=10^3
scale_factor=10^double(int8(log10(cheapest_monitor_cost*avg_cov)));
scale_factor=((10^2)/scale_factor);
cheapest_monitor_cost=cheapest_monitor_cost*scale_factor;
most_expensive_monitor_cost=most_expensive_monitor_cost*scale_factor;

disp(["Cheaper monitor cost :",cheapest_monitor_cost]);
disp(["Expensive monitor cost :",most_expensive_monitor_cost]);

% Dont forget about coverage so multiple this by coverage 
% Min budget is to approximately use 1 monitor (cheaper one - ASAN) (Greater than actual min)
min_budget=0;
% Max budget is approximately use expensive monitor for all unsafe ops (considering max coverage) (greater than actual needed max)
max_budget = most_expensive_monitor_cost*max_cov*num_unsafe_op;
% Step size is cost to add 1 additional cheaper monitor
step_size = cheapest_monitor_cost*avg_cov*2;
if need_to_run_candea
    % To compare to ASAP
    step_size = cheapest_monitor_cost*avg_cov*1;
end
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
disp(["Estimated Interesting budget value:",interesting_budget/scale_factor]);

x = [];
y2 = [];
ti1 = [];
ti2 = [];
ti3 = [];
ti4 = [];
unsafe_ops_protected_results=[];
% Objective value is sum of protection of all targets so just dividing by number of targets 
normalized_protected_targets=[];
% Similar objective value (protection) using Candea's heuristic
candea_protected_targets=[];
% Turn off annotating i.e for the instrumentation off for now
need_to_annotate_nodes=0;
changed_step_size=0;
prev_ojective=0;
stationary_iterations_limit=5;
candea_ops_covered=[];
i = min_budget;
% Set to lesser than AVG so a budget where we cannot cover all if freq is same
budge_to_eval=cheapest_monitor_cost*avg_cov*num_unsafe_op*0.0625;
asan_objective_value=[];
baggy_objective_value=[];
asan_only_unsafe_op_covered=[];
baggy_only_unsafe_op_covered=[];

selective_budgets=[budge_to_eval,2*budge_to_eval,4*budge_to_eval,8*budge_to_eval];
% k = 1;
for k = 1 : length(selective_budgets)
    budget = selective_budgets(k);
    budget_as_perc=(budget/scale_factor)*100;
    budget_as_perc=(budget_as_perc/execution_time);
    x = [x;budget_as_perc];
    [nodeList, node_montype_map, mpList, mp_to_montype_map] = build_gurobi_sign_tgroup_budgeted_model(effi_file,coverage_file,cost_file,pathweight_file,mon_type_file,accuracy_file,tgroup_file,node_num,num_mp,mon_type_num,budget,num_targets,scale_factor,monitoring_points_map,0);
    [objective_int, result_map] = minlp_gurobi('sign_budgeted_efficient_monitor.lp');
    solution_translated = translate_result(nodeList,node_montype_map,mpList,mp_to_montype_map,result_map,target_to_unsafe_operations_map);
    [curr_t1,curr_t2,curr_t3,curr_t4,unsafe_ops_protected]=analysis_mon_type(solution_translated);
    unsafe_ops_protected_results=[unsafe_ops_protected_results;(unsafe_ops_protected)];
    ti1=[ti1;(curr_t1)];
    ti2=[ti2;(curr_t2)];
    y2 = [y2;objective_int];
    normalized_protected_targets=[normalized_protected_targets;(objective_int/1)];
   

    % if need_to_annotate_nodes      
    %     if objective_int==0
    %         continue
    %     end
    %     % Relies on MP
    %     display(["Placement build budget:",budget_as_perc]);
    %     place_monitors(solution_translated,application_name);
    %     need_to_annotate_nodes=0;
    %     break;
    % end   

    % % ASAN only
    % [nodeList, node_montype_map, mpList, mp_to_montype_map] = build_gurobi_sign_tgroup_budgeted_model(effi_file,coverage_file,cost_file,pathweight_file,mon_type_file,accuracy_file,tgroup_file,node_num,num_mp,mon_type_num,budget,num_targets,scale_factor,monitoring_points_map,2);
    % [objective_int, result_map] = minlp_gurobi('sign_budgeted_efficient_monitor_asan.lp');
    % asan_objective_value = [asan_objective_value;(objective_int)];
    % solution_translated = translate_result(nodeList,node_montype_map,mpList,mp_to_montype_map,result_map);
    % [curr_t1,curr_t2,curr_t3,curr_t4,unsafe_ops_protected]=analysis_mon_type(solution_translated);
    % asan_only_unsafe_op_covered = [asan_only_unsafe_op_covered;unsafe_ops_protected];


    % % Baggy only
    % [nodeList, node_montype_map, mpList, mp_to_montype_map] = build_gurobi_sign_tgroup_budgeted_model(effi_file,coverage_file,cost_file,pathweight_file,mon_type_file,accuracy_file,tgroup_file,node_num,num_mp,mon_type_num,budget,num_targets,scale_factor,monitoring_points_map,1);
    % [objective_int, result_map] = minlp_gurobi('sign_budgeted_efficient_monitor_baggy.lp');
    % baggy_objective_value = [baggy_objective_value;(objective_int)];
    % solution_translated = translate_result(nodeList,node_montype_map,mpList,mp_to_montype_map,result_map);
    % [curr_t1,curr_t2,curr_t3,curr_t4,unsafe_ops_protected]=analysis_mon_type(solution_translated);
    % baggy_only_unsafe_op_covered = [baggy_only_unsafe_op_covered;unsafe_ops_protected];

 
end    

display(["BUDGETS:"]);
disp(x);
% display([" objective value:",y2]);
display([" Nrmal objective value:"]);
disp(normalized_protected_targets);
display(["Baggy Unsafe OPs covered:"]);
disp(ti1);
display(["ASAN Unsafe OPs covered:"]);
disp(ti2);
display(["Total Unsafe OPs covered:"]);
disp(unsafe_ops_protected_results);

% % display(["ASAN Normalized objective value:"]);
% % disp(asan_objective_value);
% % display(["ASAN only Unsafe OPs covered:"]);
% % disp(asan_only_unsafe_op_covered);
% % display(["Baggy Normalized objective value:"]);
% % disp(baggy_objective_value);
% % display(["Baggy only Unsafe OPs covered:"]);
% % disp(baggy_only_unsafe_op_covered);
% % % disp(curr_t1);



% % if need_to_run_candea==1
% %     display(["Normalized objective value:"]);
% %     disp(candea_protected_targets);
% %     display(["Total Unsafe OPs covered:"]);
% %     disp(candea_ops_covered);
% % end    

return;

num_iterations=0;
interesting_budget=budge_to_eval;
i=interesting_budget-2*step_size;
while i<=max_budget
    budget = i;
    budget_as_perc=(i/scale_factor)*100;
    budget_as_perc=(budget_as_perc/execution_time);
    x = [x;budget_as_perc];
    % Effi file
    % [nodeList, node_montype_map, mpList, mp_to_montype_map] = build_gurobi_sign_tgroup_budgeted_model("effi_file.txt",coverage_file,cost_file,pathweight_file,mon_type_file,accuracy_file,tgroup_file,node_num,num_mp,mon_type_num,budget,num_targets,scale_factor,monitoring_points_map);
    [nodeList, node_montype_map, mpList, mp_to_montype_map] = build_gurobi_sign_tgroup_budgeted_model(effi_file,coverage_file,cost_file,pathweight_file,mon_type_file,accuracy_file,tgroup_file,node_num,num_mp,mon_type_num,budget,num_targets,scale_factor,monitoring_points_map,0);
    [objective_int, result_map] = minlp_gurobi('sign_budgeted_efficient_monitor.lp');
    solution_translated = translate_result(nodeList,node_montype_map,mpList,mp_to_montype_map,result_map);
    [curr_t1,curr_t2,curr_t3,curr_t4,unsafe_ops_protected]=analysis_mon_type(solution_translated);
    unsafe_ops_protected_results=[unsafe_ops_protected_results;(unsafe_ops_protected/num_unsafe_op)];
    ti1=[ti1;(curr_t1/num_unsafe_op)];
    ti2=[ti2;(curr_t2/num_unsafe_op)];
    y2 = [y2;objective_int];
    normalized_protected_targets=[normalized_protected_targets;(objective_int/num_targets)];
    if need_to_annotate_nodes && abs(budget - interesting_budget) < step_size      
        if objective_int==0
            interesting_budget=interesting_budget+step_size
            continue
        end
        % Relies on MP
        display(["Placement build budget:",budget_as_perc]);
        place_monitors(solution_translated,application_name);
        need_to_annotate_nodes=0;
        break;
    end    
    if need_to_run_candea==1
        % Invoke candea heuristic
        candea_objective_value=get_candea_results(budget,num_unsafe_op,asan_unsafe_operation_to_monitoring_points_cost_map,unsafe_op_to_max_profit_map,cheapest_monitor_cost,asan_accuracy);
        candea_protected_targets=[candea_protected_targets;(candea_objective_value/num_targets)];
    end
    
    % display(["Objective int==num_targets:",objective_int,num_targets]);
    % display(["Objective int==num_targets:",objective_int==num_targets]);

    if uint32(objective_int)==num_targets
        break;
    % elseif  objective_int>=(0.8*num_targets)
    %     break
    elseif (unsafe_ops_protected>=(0.75*num_unsafe_op)) && (changed_step_size == 0)
        top_25_avg=((total_sum-sum_freq_75)/(0.25*num_mp_non_zero_coverage));
        display(["Hottest 25 percentile frequency avg:",top_25_avg]);
        step_size = cheapest_monitor_cost*(max_cov/10);
        display(["Changed Step size",step_size]);
        changed_step_size = 1;
    end    
    prev_ojective=objective_int;
    i=i+step_size;
    num_iterations=num_iterations+1;
end


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
%         [curr_t1,curr_t2,curr_t3,curr_t4,unsafe_ops_protected]=analysis_mon_type(solution_translated);
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



% display(ti1);
% display(ti2);



%% Based on feedback 1. Protection metric 2. Show budget wrt execution time
% fig=figure;
% yyaxis left
% pp1 = plot(x,normalized_protected_targets,'LineWidth',1);
% pp1.Color = 'b';
% pp1.LineStyle = '-';
% pp1.Marker = '*';
% title(strcat('Protection Budget: ',application_name));
% xlabel('Check Budget (%)');
% ylabel('Protection (Normalized)');
% ylim([0 1]);
% hold on;
% baggyPlot = plot(x,baggy_objective_value,'LineWidth',1);
% baggyPlot.Color = '#4DBEEE';
% baggyPlot.LineStyle = '-';
% baggyPlot.Marker = '*';
% hold on;
% % asanPlot = plot(x,asan_objective_value,'LineWidth',1);
% % asanPlot.Color = '#EDB120';
% % asanPlot.LineStyle = '-';
% % asanPlot.Marker = '*';
% % hold on;


% if need_to_run_candea==1
%     pp5 = plot(x,candea_protected_targets,'LineWidth',1);
%     pp5.Color = 'magenta';
%     pp5.LineStyle = '-';
%     pp5.Marker = '*';
%     hold on;
% end

% % yyaxis right
% % pp2 = plot(x,unsafe_ops_protected_results,'LineWidth',1);
% % pp2.Color = 'k';
% % pp2.LineStyle = ':';
% % pp2.Marker = '*';
% % hold on;
% % pp3 = plot(x,ti1,'LineWidth',1);
% % pp3.Color = 'g';
% % pp3.LineStyle = '-.';
% % pp3.Marker = 'o';
% % hold on;
% % pp4 = plot(x,ti2,'LineWidth',1);
% % pp4.Color = 'r';
% % pp4.LineStyle = '-.';
% % pp4.Marker = 'o';
% % hold on;



% % %% Add vertical line to indicate the point we are evaluating (perf). Security will be a separate eval with a few case studies
% % %% Eval only when 0 per target threshold
% % budget = selective_budgets(k);;
% % budge_to_eval=(budge_to_eval/scale_factor)*100;
% % budge_to_eval=(budge_to_eval/execution_time);
% % xline(budge_to_eval,'.','C')
% % xline(2*budge_to_eval,'.','2C')
% % xline(4*budge_to_eval,'.','4C')
% % xline(8*budge_to_eval,'.','8C')

% % ylabel('Unsafe Operations Covered (Normalized)')

% % % Candea/ASAP separate plot/experiment?
% % if need_to_run_candea==1
% %     v_legend=legend([pp1,pp5,pp2,pp3,pp4],'Overall Protection','ASAP Protection','Total Unsafe Operations Covered','Monitor 1 - BBC','Monitor 2 - ASAN','Location','Best');
% % else
% %     v_legend=legend([pp1,baggyPlot,pp2,pp3,pp4],'Overall Protection','Baggy only Protection','Total Unsafe Operations Covered','Monitor 1 - BBC','Monitor 2 - ASAN','Location','Best');
% % end
% % set(v_legend,'color','none');

% % saveas(fig,"~/Desktop/"+application_name+".pdf")
% % hold off;


