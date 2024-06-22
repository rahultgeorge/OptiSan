function solution_translated = translate_result(nodeList,node_montype_map,mpList,mp_to_montype_map,node_to_mp_map,result_map)
% Reads result (variables) and populates necessary ds
% Unsafe op info and MP info 
k = keys(result_map);
solution_translated = {};
mps_seen=[];
for i = 1 : length(result_map)
    res_str = k{i};
    % Unsafe Op id
    if contains(res_str,'x')
        node_id = str2double(extractAfter(res_str,'x'));
        if ismember(node_id, nodeList)
            % after n is the pruned id
            info = node_montype_map(node_id);
            % display([info,info_updated]);
            solution_translated = [solution_translated;info];
            monitoring_points = node_to_mp_map(node_id);
            for mp_num = 1 : length(monitoring_points)
                mp_id=monitoring_points(mp_num);
                if ismember(mp_id, mpList)
                    if ~ismember(mp_id,mps_seen)
                        mp_info = mp_to_montype_map(mp_id);
                        solution_translated = [solution_translated;mp_info];
                        mps_seen=[mps_seen;mp_id];
                    end
                end            
            end
        end
    % elseif contains(res_str,'y') 
    %     mp_id = str2double(extractAfter(res_str,'y'));
    %     if ismember(mp_id, mpList)
    %         % after n is the pruned id
    %         info = mp_to_montype_map(mp_id);
    %         % display([info,info_updated]);
    %         solution_translated = [solution_translated;info];
    %     end

    % elseif contains(res_str,'t') 
    %     target_val = result_map(res_str);
    %     target_id = extractAfter(res_str,'t');
    %     % Save it as tc, tc implies a completely protected target
    %     % display(target_id);
    %     % display(target_val);
    %     if target_val == 1
    %         % display(["Target complete",target_id,target_val]);
    %         solution_translated = [solution_translated;strcat('target_co',target_id)];
    %     else
    %         solution_translated = [solution_translated;res_str];
    %     end    
    % else    
    %     solution_translated = [solution_translated;res_str];
    end
end






