function node_num = prune_data(e_file,c_file,path_num,n_num,node_map)
%parse the files to produce MINLP .apm file
% creat Equations section of the .apm file
e_wid = fopen("effi_file.txt",'w');
e_rid = fopen(e_file,'r');
while path_num > 0
    es_num = textscan(e_rid,'%d',1,'Delimiter',';');
    s_num = transpose(es_num{:});
    fprintf(e_wid,'%d\n',s_num);
    tline = fgetl(e_rid);
    while ischar(tline) && s_num > 0
        tline = fgetl(e_rid);
        X = str2num(tline);
        for i = 1:size(X,2)
            if isKey(node_map,X(i))
                temp_node = node_map(X(i));
            else
                temp_node = size(node_map,1);
                node_map(X(i)) = temp_node;
            end
            fprintf(e_wid,'%d ',temp_node); 
        end
        s_num= s_num -1; 
        fprintf(e_wid,'\n');
    end
    path_num = path_num - 1;
end
node_num = size(node_map,1);
%showmap(node_map);
c_wid = fopen("coverage_file.txt",'w');
c_rid = fopen(c_file,'r');
coverage_map = containers.Map('KeyType','double', 'ValueType','double');%<key:new_id, value:coverage>
node_index = 1;
while node_index <= n_num
    coverage_cell = textscan(c_rid,'%d',1,'Delimiter',';');
    coverage_value = transpose(coverage_cell{:});
    if isKey(node_map,node_index)
        coverage_map(node_map(node_index)) = coverage_value;
    end
    node_index = node_index + 1;
    %tline = fgetl(e_rid);
end
for i = 0: length(coverage_map)-1
    fprintf(c_wid,'%d\n',coverage_map(i));
end
end