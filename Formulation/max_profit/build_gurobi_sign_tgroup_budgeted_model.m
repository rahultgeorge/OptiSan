function [nodeList, node_montype_map, mpList, mp_to_montype_map,node_to_mp_map] = build_gurobi_sign_tgroup_budgeted_model(em_file,coverage_file,cost_file,path_weight_file,mon_type_file,accuracy_file,tgroup_file,node_num,num_mp,mon_type_num,budget,num_tgroup,scale_factor,baggy_only_mode,object_file,application_name)
    % Unsafe op(node) list to store useful variables
    nodeList=[];
    % MP list - list of monitoring points
    mpList = [];
    %% MP info is needed to annotate (i.e) the results should be based on MP info
    % Node id to unsafe op, monitor type and position(??)
    node_montype_map = containers.Map('KeyType','double', 'ValueType','char'); 
    % MP new id to mp, mon type map (Needed to generate cost constraint)
    mp_to_montype_map = containers.Map('KeyType','double', 'ValueType','char'); 
    % Node/unsafe op to mp
    node_to_mp_map=containers.Map('KeyType','double', 'ValueType','any');

    %node_num from 0 to n-1
    %mon_type_num from 1 to t
    %x_{j,t,i}: decision variable for node j of monitor type t at path i,
    %x_{i*node_num+j*mon_type_num+t} means x_{j,t,i}
    % Effi file now includes information about monitoring points 
    
    % Relevant number of unsafe operations
    num_unsafe_op=node_num-num_mp;
    display(["# of relevant nodes",node_num]);
    display(["# of relevant unsafe ops",num_unsafe_op]);
    display(["# Monitoring points:",num_mp]);
    % Mode 1 is baggy only
    if baggy_only_mode==1
        c_file = fopen(application_name+"_sign_budgeted_efficient_monitor_baggy.lp",'w');
    % Mode 2 is asan only    
    elseif baggy_only_mode==2
        c_file = fopen(application_name+"_sign_budgeted_efficient_monitor_asan.lp",'w');    
    else
        c_file = fopen(application_name+"_sign_budgeted_efficient_monitor.lp",'w');
    end    
    %store mon type cost info
    cost_fid = fopen(cost_file,'r');
    mon_type_to_cost_map = containers.Map('KeyType','double', 'ValueType','double'); 
    for i = 1:mon_type_num
        cline = fgetl(cost_fid);
        C = str2double(cline);
        C=C*scale_factor;
        mon_type_to_cost_map(i) = C; 
        display(["type",i,": Cost:",C]);
    end
    
    
    %store coverage parameter for each monitoring point 
    % Original coverage file so uses original mp id 
    coverage_fid = fopen(coverage_file,'r');
    coverage_map = containers.Map('KeyType','double', 'ValueType','double'); 
    for j = 0 : num_mp-1
        covline = fgetl(coverage_fid);
        cov = str2double(covline);
        coverage_map(j) = cov; 
    end
    
    %store target weight parameter for each target
    pw_fileID = fopen(path_weight_file,'r');
    pw_map = containers.Map('KeyType','double', 'ValueType','double'); 
    for i = 0:num_tgroup-1
        pw_info = textscan(pw_fileID,'%d',1,'Delimiter',';');
        pw = transpose(pw_info{:});
        pw_map(i)=pw;
    end
    
    %store accuracy parameter for each unsafe operation
    accu_fileID = fopen(accuracy_file,'r');
    accu_map = containers.Map('KeyType','double', 'ValueType','double'); 
    op_index = 0;
    display(["ONlY mode:",baggy_only_mode]);
    while op_index < num_unsafe_op
        es_num = textscan(accu_fileID,'%d',1,'Delimiter',';');
        % Num of monitoring options
        s_num = transpose(es_num{:});
        aline = fgetl(accu_fileID);
        set_index = 0;
        while ischar(aline) & set_index < s_num
            accu = textscan(accu_fileID,'%f',1,'Delimiter',';');
            accu_value = transpose(accu{:});
            aline = fgetl(accu_fileID);
            if baggy_only_mode==1 && set_index==0
                accu_value = 0;
            elseif baggy_only_mode==2 && set_index==1
                % Want only ASAN so set Baggy to zero
                accu_value = 0;
            end    
            %write a[i*s]
            accu_map((op_index*s_num)+set_index) = accu_value;
            set_index = set_index + 1;
        end
        op_index = op_index + 1;
    end
    
    %store node_index and mp info
    em_fileID = fopen(em_file,'r');
    mt_fileID = fopen(mon_type_file,'r');
    op_index = 0;
    while op_index < num_unsafe_op
        %read efficient monitor file
        es_num = textscan(em_fileID,'%d',1,'Delimiter',';');
        %Num of monitor options for unsafe op
        s_num = transpose(es_num{:});
        tline = fgetl(em_fileID);
        %read monitor type file
        ttline = fgetl(mt_fileID);
        linear_flag = 1;
        % Read unsafe operation id (Same unsafe op different monitors)
        tline = fgetl(em_fileID);
        X = str2num(tline);
        while ischar(tline) && s_num > 0
            % Parse mp information (one line per monitor option)
            tline = fgetl(em_fileID);
            Y = str2num(tline);
            %monitor type
            ttline = fgetl(mt_fileID);
            T = str2num(ttline);
            % Will always be 1 dimensional we provide options per unsafe operation
            nid_new = (X(1)*num_unsafe_op*mon_type_num)+(mon_type_num*X(1))+T(1);
            %store useful variables (Unsafe op id)
            nodeList=[nodeList;nid_new];
            
            % Map monitor point to type specified and create unique ids (Remember same mp with same monitor type need not be added)
            for i = 1:size(Y,2)            
                mp_id_new = (Y(i)*num_mp*mon_type_num)+(mon_type_num*Y(i))+T(1);
                if ~ismember(mp_id_new,mpList)
                    %store useful variables (MP id)
                    mpList=[mpList;mp_id_new];
                    % MPs specified on same line are for same monitoring option
                    % mp_to_montype_map(mp_id_new)=num2str(T(1));
                    % display(["MP:",Y(i),": type ",T])
                    % M for mp and t for type
                    mp_to_montype_map(mp_id_new)= ['mp' num2str(Y(i)) 't' num2str(T(1))];
                    
                end    
            end
            s_num= s_num - 1; 
        end
        op_index = op_index + 1;
    end
    
    % Objective - Target - unsafe operation constraints
    fprintf(c_file,'Maximize\n ');
    for i = 0:num_tgroup-1
        if i ~= 0
            fprintf(c_file,' + ');
        end
        fprintf(c_file,'%d ',pw_map(i));
        fprintf(c_file,'t%d',i);
    end
    fprintf(c_file,'\n');
    
    % Read monitoring options information then write corresponding gain constraints (Gain per unsafe operation = sum of accuracy*monitor option)
    fprintf(c_file,'Subject To\n');
    em_fileID = fopen(em_file,'r');
    mt_fileID = fopen(mon_type_file,'r');
    op_index = 0;
    while op_index < num_unsafe_op
        fprintf(c_file,' C%d: ',op_index);
        position_mark1 = ftell(c_file);
        fprintf(c_file,'[');
        %read efficient monitor file
        es_num = textscan(em_fileID,'%d',1,'Delimiter',';');
        % Num of monitor options for unsafe op
        s_num = transpose(es_num{:});
        tline = fgetl(em_fileID);
        linear_flag = 1;
        % Unsafe operation
        tline = fgetl(em_fileID);
        X = str2num(tline);
        if size(X,2) == 1
            linear_flag = 1*linear_flag;
        else
            linear_flag = 0*linear_flag;
        end
        %fprintf(c_file,'int_g[');
        fprintf(c_file,'g');
        fprintf(c_file,'%d',X);
        fprintf(c_file,' - ');
        %read monitor type file
        ttline = fgetl(mt_fileID);
        set_index = 0;
        while ischar(tline) && set_index < s_num
            % Parse mp information (one line per monitor option)
            tline = fgetl(em_fileID);
            Y = str2num(tline);
            %monitor type for the monitoring option
            ttline = fgetl(mt_fileID);
            T = str2num(ttline);
            fprintf(c_file,"%.1f  ", accu_map((op_index*s_num)+set_index));
            set_index = set_index + 1;
            for i = 1:size(X,2)
                if i ~= 1
                    fprintf(c_file,'*');  
                end
                fprintf(c_file,'x');
                nid_new = (X(i)*num_unsafe_op*mon_type_num)+mon_type_num*X(i)+T(1);
                fprintf(c_file,'%d',nid_new);
                %store useful variables 
                node_montype_map(nid_new)= ['unsafe_op' num2str(X(i)) 't' num2str(T(1)) 'p' num2str(op_index)];
                %fprintf(c_file,'');
                
            end
            if s_num == set_index
                position_mark2 = ftell(c_file);
                fprintf(c_file,'] = 0\n');
                position_origin = ftell(c_file);
            else
                fprintf(c_file,' - ');
            end
        end
        if linear_flag
            %remove [] because it\s not quadratic, it is linear
            fseek(c_file,position_mark1,'bof');
            fprintf(c_file,' ');
            fseek(c_file,position_mark2,'bof');
            fprintf(c_file,' ');
            fseek(c_file,position_origin,'bof');
        end
        op_index = op_index + 1;
    end
    
    
% sum_i prod_j x_i,j <=1
em_fileID = fopen(em_file,'r');
mt_fileID = fopen(mon_type_file,'r');
c_index = op_index;
op_index = 0;
while op_index < num_unsafe_op
    fprintf(c_file,' C%d: ',c_index);
    position_mark1 = ftell(c_file);
    fprintf(c_file,'[');
    %read efficient monitor file
    es_num = textscan(em_fileID,'%d',1,'Delimiter',';');
    s_num = transpose(es_num{:});%ef_monitor_set number
    tline = fgetl(em_fileID);
    %read monitor type file
    ttline = fgetl(mt_fileID);
    linear_flag = 1;
    % Unsafe operation
    tline = fgetl(em_fileID);
    X = str2num(tline);
    if size(X,2) == 1
        linear_flag = 1*linear_flag;
    else
        linear_flag = 0*linear_flag;
    end
    while ischar(tline) && s_num > 0
        % Move the handle skip over mp information (one line per monitor option)
        tline = fgetl(em_fileID);
        %monitor type
        ttline = fgetl(mt_fileID);
        T = str2num(ttline);
        for i = 1:size(X,2)
            if i ~= 1
                fprintf(c_file,' * ');  
            end
            fprintf(c_file,'x');
            nid_new = X(i)*num_unsafe_op*mon_type_num+mon_type_num*X(i)+T(1);
            fprintf(c_file,'%d',nid_new);
            node_montype_map(nid_new)= ['unsafe_op' num2str(X(i)) 't' num2str(T(1)) 'p' num2str(op_index)];
            fprintf(c_file,'');
        end
        s_num= s_num - 1; 
        if s_num == 0
            position_mark2 = ftell(c_file);
            fprintf(c_file,']<= 1\n');
            position_origin = ftell(c_file);
        else
            fprintf(c_file,' + ');
        end
    end
    
    if linear_flag
        %remove [] because it\s not quadratic, it is linear
        fseek(c_file,position_mark1,'bof');
        fprintf(c_file,' ');
        fseek(c_file,position_mark2,'bof');
        fprintf(c_file,' ');
        fseek(c_file,position_origin,'bof');
    end
    op_index = op_index + 1;
    c_index = c_index + 1;
end
    
% x_j_p= 1 -> y_k,p =1 (indicator constraints)
em_fileID = fopen(em_file,'r');
mt_fileID = fopen(mon_type_file,'r');
op_index = 0;
while op_index < num_unsafe_op
    %read efficient monitor file
    es_num = textscan(em_fileID,'%d',1,'Delimiter',';');
    % Number of monitoring options
    s_num = transpose(es_num{:});
    tline = fgetl(em_fileID);
    %read monitor type file
    ttline = fgetl(mt_fileID);
    % Unsafe operation
    tline = fgetl(em_fileID);
    X = str2num(tline);
    while ischar(tline) && s_num > 0
        % Parse mp information
        tline = fgetl(em_fileID);
        Y = str2num(tline);
        %monitor type
        ttline = fgetl(mt_fileID);
        T = str2num(ttline);
        monitoring_points=[];
        for i = 1:size(Y,2)
            % Binary variable for unsafe operation
            nid_new = (X(1)*num_unsafe_op*mon_type_num)+(mon_type_num*X(1))+T(1);
            mp_id_new = (Y(i)*num_mp*mon_type_num)+(mon_type_num*Y(i))+T(1);
            fprintf(c_file,' C%d: ',c_index);
            fprintf(c_file,' x%d = 1 -> y%d = 1 \n',nid_new,mp_id_new);
            if ~ismember(mp_id_new,monitoring_points)
                %store useful variables (MP id)
                monitoring_points=[monitoring_points;mp_id_new];     
            end
            c_index = c_index + 1;
            % fprintf(c_file,' C%d: ',c_index);
            % fprintf(c_file,' x%d = 0 -> y%d = 0 \n',nid_new,mp_id_new);
        end
        node_to_mp_map(nid_new)=monitoring_points;
        s_num= s_num - 1; 
    end
    op_index = op_index + 1;
end
    
%% TODO - Update this (Cost constraint)
% Earlier it was c_unsafe_op_pos_monitor type, now it should be c_mp_pos_monitor_type
count = 0;
fprintf(c_file,' C%d:  ',c_index);
for j = 0:num_mp-1
    for t = 1:mon_type_num
        mp_id_new = (j*num_mp*mon_type_num)+(mon_type_num*j)+t;
        if isKey(mp_to_montype_map,mp_id_new)
            mp_info=mp_to_montype_map(mp_id_new); 
            
            if str2num(extractAfter(mp_info,'t'))==t
                coe = mon_type_to_cost_map(t)*coverage_map(j);
                fprintf(c_file,'%d ',coe);
                % J here is monitoring point id and t is monitor type
                fprintf(c_file,'c%d%d',j,t);
                if j == num_mp-1 
                    fprintf(c_file,'\n');
                else
                    fprintf(c_file,' + ');
                end        
            end
        end    
    end
end
fprintf(c_file,' <= %d\n',budget);

%% Additional constraints for per object (Make this  parameter based)
if isfile(object_file)
fid = fopen(object_file,'r');
tline = fgetl(fid);
while ischar(tline)
    % disp(tline);
    c_index=c_index+1;
    fprintf(c_file,' C%d:  ',c_index);
    fprintf(c_file,'[ ');
    X = str2num(tline);
    num_ops_group = size(X,2);
    
    % fprintf(c_file,'[ ');
    % 1 for outer
    for i = 1:num_ops_group
        outer_nid_new = (X(i)*num_unsafe_op*mon_type_num)+mon_type_num*X(i)+1;
        for j = 1:num_ops_group
            fprintf(c_file,'x');
            fprintf(c_file,'%d',outer_nid_new);
            fprintf(c_file,' * ');
            fprintf(c_file,'x');
            nid_new = (X(j)*num_unsafe_op*mon_type_num)+mon_type_num*X(j)+2;
            fprintf(c_file,'%d',nid_new);
            if j ~= num_ops_group
                fprintf(c_file,' + ');
            end   
        end
        if i ~= num_ops_group
            fprintf(c_file,' + ');
        end
    end
    % if j==1
    %     fprintf(c_file,' ] * ');
    % else
    %     fprintf(c_file,' ] ');
    % end        
    
    fprintf(c_file,' ] = 0\n');
    % fprintf(c_file,' = 0\n');

    tline = fgetl(fid);
end
end

% Doesn t work
% if isfile(object_file)
%     fid = fopen(object_file,'r');
%     tline = fgetl(fid);
%     while ischar(tline)
%         disp(tline);
%         c_index=c_index+1;
%         fprintf(c_file,' G%d:  ',c_index);
%         % fprintf(c_file,'[ ');
%         X = str2num(tline);
%         num_ops_group = size(X,2);
%         for j = 1:mon_type_num
%             fprintf(c_file,'[ ');
%             for i = 1:num_ops_group
%                 if i ~= 1
%                     fprintf(c_file,' + ');  
%                 end
%                 fprintf(c_file,'x');
%                 nid_new = (X(i)*num_unsafe_op*mon_type_num)+mon_type_num*X(i)+j;
%                 fprintf(c_file,'%d',nid_new);

%             end
%             if j==1
%                 fprintf(c_file,' ] * ');
%             else
%                 fprintf(c_file,' ] ');
%             end        
%         end
%         % fprintf(c_file,'] = 0\n');
%         fprintf(c_file,'= 0\n');

%         tline = fgetl(fid);
%     end
% end

    
%Target - group constraint
g_index = c_index;
if isfile(tgroup_file)
    g_fid = fopen(tgroup_file,'r');
    for j = 0:num_tgroup-1
        tline = fgetl(g_fid);
        g_index = g_index + 1;
        fprintf(c_file,' G%d:  ',g_index);
        % Tgroup - unsafe op (original unsafe op num/id) so replace with new 
        X = str2num(tline);
        subt_num = size(X,2) - 1;
        cov = subt_num;
        fprintf(c_file,'%d t%d - ',subt_num,j);
        for i = 1:subt_num
            if i ~= subt_num
                fprintf(c_file,'g%d - ',X(i));
            else
                fprintf(c_file,'g%d = 0\n',X(i));
            end
        end
        g_index = g_index + 1;
        fprintf(c_file,' G%d:  ',g_index);
        fprintf(c_file,'t%d >= %d\n',j, X(subt_num+1));
    end
end
    
    
    

%% TODO this needs to be modified i.e x should be based on y (decision variable for each MP )  and y should set cost variable
for j = 0:num_mp-1
    for t = 1:mon_type_num
        flag_s = 0;
        reset_position = ftell(c_file);
        flag = 0;
        nonempty = 0;
        mp_id_new = (j*num_mp*mon_type_num)+(mon_type_num*j)+t;
        if ismember(mp_id_new,mpList)
            nonempty = 1;
            if flag
                disp("flag");
                fprintf(c_file,' +');
            end
            fprintf(c_file,' S%d%d0: ',j,t);
            fprintf(c_file,' y%d = 0 -> c%d%d = 0\n',mp_id_new,j,t);
            fprintf(c_file,' S%d%d1:  y%d = 1 -> c%d%d = 1\n',j,t,mp_id_new,j,t);
            flag = 1;
            flag_s = 1;
        end
        if nonempty
            % fprintf(c_file,' <= 0 \n');
            continue;
        else
            fseek(c_file,reset_position,'bof');
        end
    end
end
    
    
% MP based indicator constraint same as Mingming\s original code (z)
%% TODO this needs to be modified i.e x should be based on y (decision variable for each MP )  and y should set cost variable
% for j = 0:num_mp-1
%     for t = 1:mon_type_num
%         flag_s = 0;
%         reset_position = ftell(c_file);
%         fprintf(c_file,' S%d%d0: ',j,t);
%         flag = 0;
%         nonempty = 0;
%         mp_id_new = (j*num_mp*mon_type_num)+(mon_type_num*j)+t;
%         if ismember(mp_id_new,mpList)
%             nonempty = 1;
%             if flag
%                 disp("flag");
%                 fprintf(c_file,' +');
%             end
%             fprintf(c_file,' z%d%d = 0 -> y%d',j,t,mp_id_new);
%             flag = 1;
%             flag_s = 1;
%         end
%         if nonempty
%             fprintf(c_file,' <= 0 \n');
%             fprintf(c_file,' S%d%d1:  z%d%d = 1 -> c%d%d = 1\n',j,t,j,t,j,t);
%         else
%             fseek(c_file,reset_position,'bof');
%         end
%     end
% end

% Original code
% for j = 0:num_mp-1
%     for t = 1:mon_type_num
%         flag_s = 0;
%         reset_position = ftell(c_file);
%         fprintf(c_file,' S%d%d0: ',j,t);
%         flag = 0;
%         nonempty = 0;
%         for i = 0:num_unsafe_op - 1
%             x_i = i*num_unsafe_op*mon_type_num+j*mon_type_num+t;
%             if ismember(x_i,nodeList)
%                 nonempty = 1;
%                 if flag
%                     disp("flag");
%                     fprintf(c_file,' +');
%                 end
%                 fprintf(c_file,' z%d%d = 0 -> x%d',j,t,x_i);
%                 flag = 1;
%                 flag_s = 1;
%             end
%         end
%         if nonempty
%             fprintf(c_file,' <= 0 \n');
%             fprintf(c_file,' S%d%d1:  z%d%d = 1 -> c%d%d = 1\n',j,t,j,t,j,t);
%         else
%             fseek(c_file,reset_position,'bof');
%         end
%     end
% end


  


    fprintf(c_file,'Bounds\nBinaries\n ');
    for i = 1:size(nodeList,1)
        fprintf(c_file,' x%d', nodeList(i));
    end
    
    for i = 1:size(mpList,1)
        fprintf(c_file,' y%d', mpList(i));
    end
    
    % for j = 0:num_mp
    %     for faux_t = 1:mon_type_num
    %         mp_id_new = (j*num_mp*mon_type_num)+(mon_type_num*j)+faux_t;
    %         fprintf(c_file,' y%d', mp_id_new);
    %     end    
    % end
    
    for j = 0:num_mp-1
        for t = 1:mon_type_num
            fprintf(c_file,' c%d%d',j,t);
        end
    end
    
    
    
    fprintf(c_file,'\nEnd\n');
    fclose('all');
end







