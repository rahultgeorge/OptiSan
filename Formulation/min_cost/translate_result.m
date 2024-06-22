function solution_translated = translate_result(node_map, nodelist,node_mon_map,result_map)
%UNTITLED2 Summary of this function goes here
%   Detailed explanation goes here
k = keys(result_map);
solution_translated = {};
for i = 1 : length(result_map)
    res_str = k{i};
    node_id = str2double(extractAfter(res_str,'x'));
    if contains(res_str,'x')
        if ismember(node_id, nodelist)
            info = node_mon_map(node_id);
            index_n = strfind(info,'n');
            node_index = sscanf(info(index_n(1)+length('n'):end),'%g',1);
            tempind = cellfun(@(x)isequal(x,node_index),values(node_map));
            tempkeys = keys(node_map);
            node_index_ori = cell2mat(tempkeys(tempind));
            info_updated = ['n' num2str(node_index_ori) 'm' extractAfter(info,'m')];
            solution_translated = [solution_translated;info_updated];
        end
    else
        solution_translated = [solution_translated;res_str];
    end
end
end

