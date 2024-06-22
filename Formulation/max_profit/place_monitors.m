function place_monitors(node_monitor_info,application_name)
resultant_placement_file = fopen("result_placement.txt",'w');
for i = 1 : length(node_monitor_info)
    node_info = node_monitor_info(i);
    if contains(node_info,'mp')
        node_id=str2double(extractBefore(extractAfter(node_info,'mp'),'t'));
        monitor_type=str2double(extractAfter(node_info,'t'));
        % display([node_info,"MP ID",node_id," TYPE:",monitor_type])
        fprintf(resultant_placement_file,'%d %d\n',node_id,monitor_type);
    end
end
application_name=convertStringsToChars(application_name);
systemCommand=['python3 place_monitors.py',' ',application_name];
% Pyrun fails to identify module , also pass program name
system(systemCommand);





