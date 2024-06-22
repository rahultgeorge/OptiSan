function [node_num,num_mp] = prune_data(e_file,c_file,n_num,unsafe_op_map,monitoring_points_map)
%parse the files to produce MINLP .apm file
% creat Equations section of the .apm file
e_wid = fopen("effi_file.txt",'w');
e_rid = fopen(e_file,'r');
%  generates node map (relevant nodes), maps original ids to sequential ids in a new effi file and stores relevant coverage information into file
% Effi file contains MP information now
num_op=n_num;

% Read file and store MPs first 
while num_op > 0
    es_num = textscan(e_rid,'%d',1,'Delimiter',';');
    s_num = transpose(es_num{:});
    fprintf(e_wid,'%d\n',s_num);
    tline = fgetl(e_rid);
    % Add unsafe operation to node map
    tline = fgetl(e_rid);
    X = str2num(tline);
    for i = 1:size(X,2)
        if isKey(unsafe_op_map,X(i))
            temp_node = unsafe_op_map(X(i));
        else
            temp_node = size(unsafe_op_map,1);
            unsafe_op_map(X(i)) = temp_node;
        end
        fprintf(e_wid,'%d\n',temp_node); 
    end
    % Iterating over mp information (MP can be unsafe op (ASAN)
    while ischar(tline) && s_num > 0
        tline = fgetl(e_rid);
        X = str2num(tline);
        for i = 1:size(X,2)
            if isKey(monitoring_points_map,X(i))
                temp_node = monitoring_points_map(X(i));
            else
                temp_node = size(monitoring_points_map,1);
                monitoring_points_map(X(i)) = temp_node;
            end
            fprintf(e_wid,'%d ',temp_node); 
        end
        s_num= s_num -1; 
        fprintf(e_wid,'\n');
    end
    num_op = num_op - 1;
end

num_mp = size(monitoring_points_map,1);
node_num = size(unsafe_op_map,1)+num_mp;


end

