function [candea_objective_value, num_candea_ops_covered] = get_candea_results(budget,num_unsafe_op,asan_unsafe_operation_to_monitoring_points_cost_map,unsafe_op_to_max_profit_map,cheapest_monitor_cost,asan_accuracy)
% Candea used cost level - fraction of dyn checks to preserve - this is the check budget so basically we remove expensive ones or keep adding cheap ones till we can
covered_unsafe_operations=[];
unsafe_op_keys = cell2mat(asan_unsafe_operation_to_monitoring_points_cost_map.keys);
check_frequency_values = cell2mat(asan_unsafe_operation_to_monitoring_points_cost_map.values);
[~, sortIdx] = sort( check_frequency_values );
candea_objective_value = 0.0;
num_candea_ops_covered = 0;
curr_cost = 0.0 ; 
% display(budget);
for i = 1:num_unsafe_op
   unsafe_op = unsafe_op_keys(sortIdx(i));
   freq = check_frequency_values(sortIdx(i)); 
   curr_cost = curr_cost + (freq * cheapest_monitor_cost);
   % display(curr_cost);

   if freq>0 && curr_cost >= budget
        break;
   end
   % display(unsafe_op);
   % display(freq);
   % display(unsafe_op_to_max_profit_map(unsafe_op)); 
   candea_objective_value = candea_objective_value + (asan_accuracy *  unsafe_op_to_max_profit_map(unsafe_op)) ;
   num_candea_ops_covered=num_candea_ops_covered+1;
end
display(["Candea objective:",candea_objective_value]);    
display(["# UPAs covered:",num_candea_ops_covered]);    

