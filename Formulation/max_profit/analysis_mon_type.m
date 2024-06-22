function [t1,t2,targets_complete,all_targets_protected,unsafe_ops_protected]=analysis_mon_type(solution)
%Extract the number of monitors of each type per unsafe operation 
t1 = 0;
t2 = 0;
targets_complete = 0;
all_targets_protected = 0;
for i = 1 : length(solution)
    res_str = solution(i);
    if contains(res_str,'unsafe_op')
        type_id = extractBefore(extractAfter(res_str,'unsafe_op'),'p');
        type_id = str2double(extractAfter(type_id,'t'));
        switch type_id
            case 1
                % display([res_str,":",type_id])
                t1 = t1 + 1;
            case 2
                t2 = t2 + 1;
        end
    elseif contains (res_str,'target_co')
        targets_complete = targets_complete + 1;   
        all_targets_protected = all_targets_protected + 1;     
    elseif contains (res_str,'t')
        all_targets_protected = all_targets_protected + 1;     
    end    
end
unsafe_ops_protected=t1+t2;
end




