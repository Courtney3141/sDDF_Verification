#!/usr/bin/env python3

import sys
import re

test = 1
current_core = 0
core_totals = [0,0,0,0]
pd_totals = [0,0,0,0]
core_results = [0,0,0,0]
measurement_results = [[],[],[],[]]
pmu = {}

def result_string(pd, tu, ku, uu, ke, s, u):
    return pd + "," + str(tu) + "," + str(ku) + "," + str(uu) + "," + str(ke) + "," + str(s) + "," + str(u)

def finish_and_print():
    # Add idle thread
    for i in range(4):
        idle_util = 1 - (pd_totals[i]/core_totals[i])
        measurement_results[i].append(result_string("IDLE " + str(i), core_totals[i] - pd_totals[i], 0, 0, 0, 0, idle_util))

    # Print results
    print("CORE TOTALS")
    print('\n'.join(core_results), end ='\n\n')
    for i in range(4):
        print("CORE " + str(i) + " PROTECTION DOMAINS")
        print('\n'.join(measurement_results[i]))
    
    print(f"TOTAL CPU UTIL: 4 * {sum(pd_totals)} / {sum(core_totals)} = {4 * (sum(pd_totals) / sum(core_totals))}")

    # Clear globals
    for i in range(4):
        pd_totals[i] = 0
        measurement_results[i].clear()

print("Component,Total Cycles,Kernel Cycles,User Cycles,Kernel Entries,Schedules,Per Core CPU Utilisation")
file = sys.argv[1]
with open(file, "r") as f:
    for line in f:
        # New benchmark started
        if re.match("measurement starting...", line):
            if core_totals[0]:
                finish_and_print()
                test += 1
                print()
            print("TEST", test)
            continue
            
        # Change core
        match = re.match("{CORE ([0-9]*):",line)

        if match:
            current_core = eval(match.group(1))
            line = next(f)

        # Capture core utilisation details
        match = re.match("Utilisation details for PD: ([a-zA-Z _0-3]*) .*", line)
        if match and match.group(1) == "CORE TOTALS":
            kernel_util = eval(next(f)[-19:-1])
            kernel_entries = eval(next(f)[-19:-1])
            schedules = eval(next(f)[-19:-1])
            total_util = eval(next(f)[-19:-1])
            user_util = total_util - kernel_util

            core_string = result_string("CORE " + str(current_core), total_util, kernel_util, user_util, kernel_entries, schedules, 0)
            core_totals[current_core] = total_util
            core_results[current_core] = core_string

        # Protection domain utilisation details
        elif match:
            pd = match.group(1)
            kernel_util = eval(next(f)[-19:-1])
            kernel_entries = eval(next(f)[-19:-1])
            schedules = eval(next(f)[-19:-1])
            total_util = eval(next(f)[-19:-1])
            user_util = total_util - kernel_util
            pd_util = total_util/core_totals[current_core]

            pd_totals[current_core] += total_util
            pd_string = result_string(pd, total_util, kernel_util, user_util, kernel_entries, schedules, pd_util)
            measurement_results[current_core].append(pd_string)

        # Capture PMU details
        else:
            match = re.match("([\d\w -]+): (0x[0-9a-f]{16})", line)
            if match and "psci" not in match.group(1):
                # it's a pmu data thing.
                if match.group(1) not in pmu:
                    pmu[match.group(1)] = []
                pmu[match.group(1)].append(eval(match.group(2)))

# Print results from last test
if core_totals[0]:
    finish_and_print()
    print()

# Print PMU data
if pmu:
    # Find length of one of the entries
    length = len(pmu["Instructions"])
    print(','.join(pmu.keys()))
    for i in range(0,length):
        for key in pmu.keys():
            if i == 0 and len(pmu[key]) != length:
                print("Length of 'Instructions' (" + str(length) + ") and '" + key + "' (" + str(len(pmu[key])) + ") don't match!")
                exit()
            print(str(pmu[key][i]) + ",", end = '')
        print("\n", end = '')
