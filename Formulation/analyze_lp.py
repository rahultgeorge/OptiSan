#!/usr/bin/python3

from gurobipy import *
import sys

m = read(sys.argv[1])
m.optimize()
m.computeIIS()
m.write('infeasible.ilp')
