function [objective, result_map] = minlp_gurobi(filename)

% Copyright 2020, Gurobi Optimization, LLC
%
% This example reads a MIP model from a file, solves it and prints
% the objective values from all feasible solutions generated while
% solving the MIP. Then it creates the associated fixed model and
% solves that model.

% Read model
fprintf('Reading model %s\n', filename);

model = gurobi_read(filename);

cols = size(model.A, 2);

ivars = find(model.vtype ~= 'C');
ints = length(ivars);

if ints <= 0
    fprintf('All variables of the model are continuous, nothing to do\n');
    return;
end

% Optimize
%params.poolsolutions = 5;
%params.poolsearchmode=2;
% params.FeasibilityTol=1e-3
% params.OptimalityTol=1e-9
params.dualreductions=0;
%params.InfUnbdInfo=1;
result = gurobi(model, params);

% Capture solution information
if ~strcmp(result.status, 'OPTIMAL')
    fprintf('This model cannot be solved because its optimization status is %s\n', ...
        result.status);
        objective=0;
        result_map = containers.Map('KeyType','char', 'ValueType','double'); 
    if strcmp(result.status, 'UNBOUNDED')
        fprintf('Unbd ray: %s\n',result.unbdray);
    end
    return;
end

% Iterate over the solutions
if isfield(result, 'pool') && ~isempty(result.pool)
    solcount = length(result.pool);
    for k = 1:solcount
        fprintf('Solution %d has objective %g\n', k, result.pool(k).objval);
%{      
        asan_upa=0;
        baggy_upa=0;
        for j = 1:cols
            if contains(model.varnames{j},'x')
                % Tolerance
                if abs(result.pool(k).xn(j)) > 1e-6
                    display(model.varnames{j});
                    if model.varnames{j}(end)=='1'
                        baggy_upa=baggy_upa+1;
                    else
                        asan_upa=asan_upa+1;
                    end    
                    % fprintf('%s %g\n', model.varnames{j}, result.pool(k).xn(j));
                end
            end
        end
        display(asan_upa);
        display(baggy_upa);
%}
    end
else
    fprintf('Solution 1 has objective %g\n', result.objval);
end

% Convert to fixed model
%%% TODO - Ask Mingming why not use .fixed and also what about binary variables 
for j = 1:cols
    if model.vtype(j) ~= 'C'
        %fprintf("Var name: %s, value:%g, %s \n",model.varnames{j},result.x(j),model.vtype(j))
        t = floor(result.x(j) + 0.5);
        model.lb(j) = t;
        model.ub(j) = t;
    end
end


% Solve the fixed model
result2 = gurobi(model, params);
if ~strcmp(result2.status, 'OPTIMAL')
    fprintf('Error: fixed model is not optimal\n');
    objective=0;
    result_map = containers.Map('KeyType','char', 'ValueType','double'); 
    return;
end
if abs(result.objval - result2.objval) > 1e-6 * (1 + abs(result.objval))
    fprintf('Error: Objective values differ\n');
end
objective = result.objval
result_map = containers.Map('KeyType','char', 'ValueType','double'); 
% Print & Store values of non-zero variables
for j = 1:cols
    % Tolerance
    if abs(result2.x(j)) > 1e-6
        fprintf('%s %g\n', model.varnames{j}, result2.x(j));
        result_map(model.varnames{j})= result2.x(j);
    end
end



