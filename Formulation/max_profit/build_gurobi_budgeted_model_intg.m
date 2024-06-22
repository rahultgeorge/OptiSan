function [nodelist,node_montype_map] = build_gurobi_budgeted_model_intg(em_file,coverage_file,cost_file,path_weight_file,mon_type_file,accuracy_file,path_num,node_num,mon_type_num,budget)
% node list to store useful variables
nodelist=[];
node_montype_map = containers.Map('KeyType','double', 'ValueType','char'); 
%node_num from 0 to n-1
%mon_type_num from 1 to t
%path_num from 0 to m-1
%x_{j,t,i}: decision variable for node j of monitor type t at path i,
%x_{i*node_num+j*mon_type_num+t} means x_{j,t,i}
%parse the files to produce MINLP .apm file
% creat Equations section of the .apm file
%

c_file = fopen("budgeted_efficient_monitor.lp",'w');

%store mon type cost info
cost_fid = fopen(cost_file,'r');
mon_type_map = containers.Map('KeyType','double', 'ValueType','double'); 
for i = 1:mon_type_num
    cline = fgetl(cost_fid);
    C = str2double(cline);
    mon_type_map(i) = C; 
end
%store coverage parameter for each nodes
coverage_fid = fopen(coverage_file,'r');
coverage_map = containers.Map('KeyType','double', 'ValueType','double'); 
for j = 0 : node_num-1
    covline = fgetl(coverage_fid);
    cov = str2double(covline);
    coverage_map(j) = cov; 
end

%store path_weight parameter for each nodes
pw_fileID = fopen(path_weight_file,'r');
pw_map = containers.Map('KeyType','double', 'ValueType','double'); 
for i = 0:path_num-1
    pw_info = textscan(pw_fileID,'%d',1,'Delimiter',';');
    pw = transpose(pw_info{:});
    pw_map(i)=pw;
end

%store accuracy parameter for each efficient monitor set
accu_fileID = fopen(accuracy_file,'r');
accu_map = containers.Map('KeyType','double', 'ValueType','double'); 
path_index = 0;
while path_index < path_num
    es_num = textscan(accu_fileID,'%d',1,'Delimiter',';');
    s_num = transpose(es_num{:});%ef_monitor_set number
    aline = fgetl(accu_fileID);
    set_index = 0;
    while ischar(aline) & set_index < s_num
        accu = textscan(accu_fileID,'%f',1,'Delimiter',';');
        accu_value = transpose(accu{:});
        aline = fgetl(accu_fileID);
        %write a[i*s]
        accu_map(path_index*s_num+set_index) = accu_value;
        set_index = set_index + 1;
    end
    path_index = path_index + 1;
end

%store node_index info
em_fileID = fopen(em_file,'r');
mt_fileID = fopen(mon_type_file,'r');
path_index = 0;
while path_index < path_num
    %read efficient monitor file
    es_num = textscan(em_fileID,'%d',1,'Delimiter',';');
    s_num = transpose(es_num{:});%ef_monitor_set number
    tline = fgetl(em_fileID);
    %read monitor type file
    ttline = fgetl(mt_fileID);
    linear_flag = 1;
    while ischar(tline) && s_num > 0
        %efficient monitor
        tline = fgetl(em_fileID);
        X = str2num(tline);
        if size(X,2) == 1
            linear_flag = 1*linear_flag;
        else
            linear_flag = 0*linear_flag;
        end
        %monitor type
        ttline = fgetl(mt_fileID);
        T = str2num(ttline);
        for i = 1:size(X,2)
            nid_new = path_index*node_num*mon_type_num+mon_type_num*X(i)+T(i);
            %store useful variables
            nodelist=[nodelist;nid_new];
        end
        s_num= s_num - 1; 
    end
    path_index = path_index + 1;
end


fprintf(c_file,'Maximize\n ');
for i = 0:path_num-1
    if i ~= 0
        fprintf(c_file,' + ');
    end
    fprintf(c_file,'%d ',pw_map(i));
    fprintf(c_file,'g%d',i);
end
fprintf(c_file,'\n');

% read efficient monitor set information then write corresponding
% constraints
fprintf(c_file,'Subject To\n');
em_fileID = fopen(em_file,'r');
mt_fileID = fopen(mon_type_file,'r');
path_index = 0;
while path_index < path_num
    fprintf(c_file,' C%d: ',path_index);
    position_mark1 = ftell(c_file);
    fprintf(c_file,'[');
    %read efficient monitor file
    es_num = textscan(em_fileID,'%d',1,'Delimiter',';');
    s_num = transpose(es_num{:});%ef_monitor_set number
    tline = fgetl(em_fileID);
    %fprintf(c_file,'int_g[');
    fprintf(c_file,'g');
    fprintf(c_file,'%d',path_index);
    fprintf(c_file,' - ');
    %read monitor type file
    ttline = fgetl(mt_fileID);
    linear_flag = 1;
    set_index = 0;
    while ischar(tline) && set_index < s_num
        %efficient monitor
        tline = fgetl(em_fileID);
        X = str2num(tline);
        if size(X,2) == 1
            linear_flag = 1*linear_flag;
        else
            linear_flag = 0*linear_flag;
        end
        %monitor type
        ttline = fgetl(mt_fileID);
        T = str2num(ttline);
%        fprintf(c_file,"%.1f  ", accu_map(path_index*s_num+set_index));
        set_index = set_index + 1;
        for i = 1:size(X,2)
            if i ~= 1
                fprintf(c_file,'*');  
            end
            fprintf(c_file,'x');
            nid_new = path_index*node_num*mon_type_num+mon_type_num*X(i)+T(i);
            fprintf(c_file,'%d',nid_new);
            %store useful variables
            node_montype_map(nid_new)= ['n' num2str(X(i)) 'm' num2str(T(i)) 'p' num2str(path_index)];
            %fprintf(c_file,'');
        end
        if s_num == set_index
            position_mark2 = ftell(c_file);
            fprintf(c_file,'] <= 0\n');
            position_origin = ftell(c_file);
        else
            fprintf(c_file,' - ');
        end
    end
    if linear_flag
    %remove [] because it's not quadratic, it is linear
       fseek(c_file,position_mark1,'bof');
       fprintf(c_file,' ');
       fseek(c_file,position_mark2,'bof');
       fprintf(c_file,' ');
       fseek(c_file,position_origin,'bof');
    end
    
    path_index = path_index + 1;
end

count = 0;
fprintf(c_file,' C%d: ',path_index);
flag_s = 0; 
for j = 0:node_num-1
    %fprintf(c_file,' c[%d] * ',j);
    for t = 1:mon_type_num
        flag = 0;
        for i = 0:path_num - 1
            x_i = i*node_num*mon_type_num+j*mon_type_num+t;
            if ismember(x_i,nodelist)
                coef = coverage_map(j)*mon_type_map(t);
                fprintf(c_file,'%d ',coef);
                if flag
                    fprintf(c_file,' + ');
                end
                fprintf(c_file,'x%d',x_i);
                flag = 1;
                flag_s = 1;
            end
        end 
        if j == node_num - 1 & t == mon_type_num
            count = count + 1;
        elseif flag_s
            fprintf(c_file,' + ');
            flag_s = 0;
        end
    end
end
fprintf(c_file,' < %d\n',budget);

fprintf(c_file,'Bounds\nBinaries\n ');
for i = 1:size(nodelist,1)
    fprintf(c_file,' x%d', nodelist(i));
end
for i = 0: path_num-1
    fprintf(c_file,' g%d',i);
end
fprintf(c_file,'\nEnd\n');
fclose('all');
end

