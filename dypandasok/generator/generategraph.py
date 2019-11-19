#!/usr/bin/python3

import os
import re
import sys
import pydot
import json
import bisect

# generates process key for pydot process Cluster subgraph
# in pid = integer, process id
# in asid = integer, process cr3
# return string
def genProcessKey(pid, asid):
    return 'process_%d_%x' % (pid, asid)

# generates process label for pydot process Cluster subgraph
# process label is shown in the graph if exists. Otherwise, the 'key' is shown,
# in as generated by genProcessKey
# in pid = integer, process id
# in asid = integer, process cr3
# return string
def genProcessLabel(pid, asid):
    return 'process pid=%d asid=%x' % (pid, asid)

# generates layer key for pydot layer Cluster subgraph
# in pid = integer, process id
# in layer_no = integer, layer number
# in nFrames =  integer, the number of frames for that layer
# return string
def genLayerKey(pid, layer_no, nFrames):
    return "%d#%d#%d" % (pid, layer_no, nFrames)

# generates layer label for pydot layer Cluster subgraph
# if layer label exists, it is shown in the generated graph instead of the layer key
# in pid = integer, process id
# in layer_no = integer, layer number
# in nFrames =  integer, the number of frames for that layer
# return string
def genLayerLabel(pid, layer_no, nFrames):
    return "layer %d, frames %d" % (layer_no, nFrames)

# generates key for memory range for pydot memory range Node
# in pid = integer, process id
# in layer_no = integer, layer number
# in memloc = string, code for memory location (M = Module, S = stack, H = heap, L = library, X = unknown)
# in num_startAddr = integer, start address of memory range
# in num_execLength = integer, length of memory range
# in pprange_start = integer, minimum program point for execution done in this memory range
# in pprange_end = integer, maximum program point for execution done in this memory range
# return string
def genNodeKey(pid, layer_no, memloc, num_startAddr, num_execLength, pprange_start, pprange_end):
    return "%d#%d#%s#%x#%x#%d#%d" % (pid, layer_no, memloc, num_startAddr, num_execLength, pprange_start, pprange_end)

# generates label for memory range for pydot memory range Node. If label exists, this will be shown instead of the node key
# in memloc = string, code for memory location (M = Module, S = stack, H = heap, L = library, X = unknown)
# in num_startAddr = integer, start address of memory range
# in num_execLength = integer, length of memory range
# in pprange_start = integer, minimum program point for execution done in this memory range
# in pprange_end = integer, maximum program point for execution done in this memory range
# in frame = integer, number of frames in this memory range
# in n_uniq_apis = integer, number of unique api calls
# in n_apis = integer, number of api calls
# in str_api_groups = string api groups called
# return string
def genNodeLabel(memloc, num_startAddr, num_execLength, pprange_start, pprange_end, frame, n_uniq_apis, n_apis, str_api_groups):
    return "%s %x\n%x\n%d->%d\n%d\n%d %d %s" % (memloc, num_startAddr, num_execLength, pprange_start, pprange_end, frame, n_uniq_apis, n_apis, str_api_groups)

# simplify check and tally value
# in mp = python dict, the target dict to tally
# in key = object, key of dict to tally
# in inc = integer, default 1, if key not exist, tally set to inc. Otherwise, the tally is added by inc
# return void
def incMapFromZero(mp, key, inc = 1):
    if key in mp:
        mp[key] += inc
    else:
        mp[key] = inc

# merge and add counters of two maps
# in-out mapAddedTo 
# in mapAddedFrom
# return void
def mergeAndAddCounters(mapAddedTo, mapAddedFrom):
    for key in mapAddedFrom:
        incMapFromZero(mapAddedTo, key, mapAddedFrom[key])

# creates pydot Cluster for each process
# in pyd_graph = pydot Dot object, pydot topmost level graph, created by pydot.Dot class
# out pyd_processBlocks = dict, the output dict where pydot process Clusters are placed
# in jsonData = json dict, the dict generated from reading given json log file
# return void
def createPydProcesses(pyd_graph, pyd_processBlocks, jsonData):
    for pjs in jsonData:
        if pjs == {}: # this is added as sentinel character
            continue
        
        process = pjs['process']
        pyd_processBlock = pydot.Cluster(genProcessKey(process['pid'], process['asid']), 
                label = genProcessLabel(process['pid'], process['asid']), shape = 'rectangle')
        pyd_processBlocks[process['pid']] = pyd_processBlock
        pyd_graph.add_subgraph(pyd_processBlock)

# generates the memory ranges for each layer, however, the pydot Node objects are not yet created because there are still some
# information that are required such as the colors of the Node. Once the objects are created, it seems that they are immutable
# So, the actual pydot Node object creation is deferred until all information are collected.
#
# in order to simplify the output result image.
# the disjoint consecutive execution address will be combined if the smallest distance between them is < 4KB, based on
# packerinspector reference, just for visualization
# without this, there will be too many memory ranges and the graph becomes unreadable.
#
# in pyd_graph = pydot Dot object, pydot topmost level graph, created by pydot.Dot class
# in pyd_processBlocks = dict, the dict of pydot process Clusters
# out pyd_execNodes = dict, the dict for output nodes
# out pyd_layerBlocks = dict, the dict for layers
# in jsonData = dict, the python dict for json input data
# return void
def createPydExecutionLayerNodes(pyd_graph, pyd_processBlocks, pyd_execNodes, pyd_layerBlocks, jsonData):
    for processJson in jsonData:
        if processJson == {}:
            continue
        
        processKey = processJson['process']
        processPid = processKey['pid']
        
        layers = processJson['layers']
        #last_exec_instrs = processJson['last_executing_instructions']
        
        for layer in layers:
            if layer == {}:
                continue
            
            lastMemSegment = {}
            layer_no = layer['layer_no']
            executions = layer['executions']
            
            nFrames = 0
            
            for execution in executions:
                if execution == {}:
                    continue
                    
                frames = execution['frames'] # number
                
                # don't sum, just find max then
                #nFrames += frames
                nFrames = max(nFrames, frames)
            
            # for every layer, assign same rank for ALL nodes inside it, makes all nodes in each layer placed in horizontal and flat.
            pyd_layerBlock = pydot.Cluster(genLayerKey(processPid, layer_no, nFrames), 
                    label = genLayerLabel(processPid, layer_no, nFrames), shape = 'rectangle', rank = "same")
            pyd_layerBlocks[(processPid, layer_no)] = pyd_layerBlock
            pyd_processBlocks[processPid].add_subgraph(pyd_layerBlock)
            # pyd_graph.add_subgraph(pyd_layerBlock)
            
            for execution in executions:
                if execution == {}:
                    continue
                
                execRange = execution['execution'] # object
                memloc = execution['memory_location'] # string
                frames = execution['frames'] # number
                #transition_sources = execution['transitions_sources'] # array of objects
                #writes = execution['writes'] # array of objects
                pprange = execution['program_points'] # object
                api_ctrmap = execution['api_counter']['api_count']
                api_group_ctrmap = execution['api_counter']['group_count']
                
                #execStartAddr = execRange['start_addr']
                #execEndAddr = execRange['end_addr']
                #execSize = execRange['size']
                
                # node_a = pydot.Node("Node A", style="filled", fillcolor="red", shape="box")
                # nodekey params: memloc, num_startAddr, num_execLength, pprange
                #pyd_execNode = pydot.Node(genNodeKey(processPid, layer_no, memloc, execRange['start_addr'], execRange['size'], pprange),
                #        label = genNodeLabel(memloc, execRange['start_addr'], execRange['size'], pprange, frames),
                #        style="filled", fillcolor="#ffffff", shape="box")
                
                if lastMemSegment == {}:
                    lastMemSegment = {
                        'pid': processPid,
                        'layer_no': layer_no,
                        'start_addr': execRange['start_addr'],
                        'length': execRange['size'],
                    #    'pyd': pyd_execNode,
                        'memloc': memloc,
                        'frames': frames,
                        'pprange': (pprange['start'], pprange['end']),
                        #'pprange_obj': pprange,
                        
                        # key = node id: (processPid, layer_no, execRange['start_addr']), value = total number of transitions (integer)
                        # not filled in this function
                        'transition': {},
                        
                        # key = (processPid, layer_no, execRange['start_addr']), value = total number of writes (integer)
                        # not filled in this function
                        'writes': {},
                        
                        # key = <Virtual Address of function in hex> in string, val = count of apis, in integer
                        'uniq_api_count_map': api_ctrmap,
                        
                        # key = api group name, val = count of apis, in integer
                        'api_group_count_map': api_group_ctrmap
                    }
                    
                else:
                    if execRange['start_addr'] - (lastMemSegment['start_addr'] + lastMemSegment['length']) <= 4096:
                        lastMemSegment['length'] = execRange['start_addr'] - lastMemSegment['start_addr'] + execRange['size']
                        if 'frames' in lastMemSegment:
                            lastMemSegment['frames'] = max(frames, lastMemSegment['frames'])
                        else:
                            lastMemSegment['frames'] = frames
                        lastMemSegment['pprange'] = ( min(lastMemSegment['pprange'][0], pprange['start']), max(lastMemSegment['pprange'][1], pprange['end']) )
                        mergeAndAddCounters(lastMemSegment['uniq_api_count_map'], api_ctrmap)
                        mergeAndAddCounters(lastMemSegment['api_group_count_map'], api_group_ctrmap)
                        
                    else:
                        pyd_execNodes[(lastMemSegment['pid'], lastMemSegment['layer_no'], lastMemSegment['start_addr'])] = lastMemSegment
                        lastMemSegment = {
                            'pid': processPid,
                            'layer_no': layer_no,
                            'start_addr': execRange['start_addr'],
                            'length': execRange['size'],
                        #    'pyd': pyd_execNode,
                            'memloc': memloc,
                            'frames': frames,
                            'pprange': (pprange['start'], pprange['end']),
                         #   'pprange_obj': pprange,
                            
                            # key = node id: (processPid, layer_no, execRange['start_addr']), value = total number of transitions (integer)
                            'transition': {},
                            
                            # key = (processPid, layer_no, execRange['start_addr']), value = total number of writes (integer)
                            'writes': {}, 
                            
                            'uniq_api_count_map': api_ctrmap,
                            
                            'api_group_count_map': api_group_ctrmap
                        }
                    
                
                #pyd_execNodes[(processPid, layer_no, execRange['start_addr'])] = {
                #    'pid': processPid,
                #    'layer_no': layer_no,
                #    'start_addr': execRange['start_addr'],
                #    'length': execRange['size'],
                # #   'pyd': pyd_execNode,
                #    'memloc': memloc,
                #    'frames': frames,
                #    'pprange': (pprange['start'], pprange['end']),
                #   # 'pprange_obj': pprange,
                #    
                #    # key = node id: (processPid, layer_no, execRange['start_addr']), value = total number of transitions (integer)
                #    'transition': {},
                #    
                #    # key = (processPid, layer_no, execRange['start_addr']), value = total number of writes (integer)
                #    'writes': {}
                #}
                #pyd_layerBlock.add_node(pyd_execNode)
                #pyd_graph.add_node(pyd_execNode)
                
                pyd_execNodes[(lastMemSegment['pid'], lastMemSegment['layer_no'], lastMemSegment['start_addr'])] = lastMemSegment
    
# checks for overlapping ranges, if any
# in node_addresses = list of triple(pid, layer_no, start_addr) sorted ascending by pid, layer_no and start_addr.
# in pyd_execNodes = dict of memory ranges
# return void
# throw AssertionError if overlapping memory ranges are found
def checkOverlapping(node_addresses, pyd_execNodes):
    last_addr = (0, 0, 0)
    
    # make sure no overlaps among execution ranges in one layer
    for na in node_addresses:
        size = pyd_execNodes[na]['length']
        if last_addr != (0, 0, 0):
            if last_addr[0] == na[0] and last_addr[1] == na[1]:
                end_addr = last_addr[2]
                assert(end_addr <= na[2]), "Error, Overlapping execution detected in one layer for pid=%d, layer_no=%d, ends_in=%d and start_addr=%d" % (na[0], na[1], end_addr, na[2])
                
        last_addr = (na[0], na[1], na[2] + size)

# group memory ranges based on their pid and layer number
# in pyd_execNodes = dict of the memory ranges
# return dict, key = tuple (pid, layer_no), value = list of memory range nodes in specified pid and layer number.
def splitExecNodeToPerPidLayer(pyd_execNodes):
    pyd_execNodesPerPidLayer = {}
    for kp in pyd_execNodes:
        nkp = (kp[0], kp[1])
        if nkp in pyd_execNodesPerPidLayer:
            pyd_execNodesPerPidLayer[nkp].append(pyd_execNodes[kp])
        else:
            pyd_execNodesPerPidLayer[nkp] = [pyd_execNodes[kp]]
            
    return pyd_execNodesPerPidLayer

# since pyd_execNodes is the summarization / combination of execution entries,
# it won't find the keys exactly, as seen in execution
# this function is to find the entry in pyd_execNodes that covers the execNodeKey entirely
# 
# in pyd_execNodes = dict of the memory ranges
# in execNodeKey = triple(pid, layer_no, start_addr) of the searched address
# in node_addresses = list of triple(pid, layer_no, start_addr) sorted ascending by pid, layer_no and start_addr.
# in execSize = integer, actual memory range size in json data. pyd_execNodes 
#               combines memory ranges with equal or less than 4096 bytes difference.
#
# return the value of pyd_execNodes that covers memory range specified.
# throw AssertionError if no memory range found, unsorted node_addresses
def findKeyOnExecNodes(pyd_execNodes, execNodeKey, node_addresses, execSize):
    if execNodeKey in pyd_execNodes:
        return pyd_execNodes[execNodeKey]
    
    node_addresses_len = len(node_addresses)
    
    search_pid = execNodeKey[0]
    search_layer_no = execNodeKey[1]
    search_start_addr = execNodeKey[2]
    search_exec_size = execSize
    
    idx = bisect.bisect_left(node_addresses, execNodeKey)
    
    if idx < node_addresses_len:
        node_addr = node_addresses[idx]
        region_size = pyd_execNodes[node_addr]['length']
        
        print("node_addr: %s" % str(node_addr))
        
        if node_addr[0] == search_pid and node_addr[1] == search_layer_no:
            if node_addr[2] == search_start_addr:
                if search_exec_size <= region_size:
                    return pyd_execNodes[node_addr]
                else:
                    assert(False), "search size %d is greater than the region size %d for address %x" % (search_exec_size, region_size, search_start_addr)
                
            elif node_addr[2] > search_start_addr:
                if idx == 0:
                    # the current node address is larger than source addr
                    assert(False), "Error, Not found in array"
                        
                else:
                    # check idx - 1
                    idx -= 1
            
            else:
                assert(False), "Unknown error, should not happen"
        else:
            idx -= 1
            #assert(False), "Error, unknown transition source from source 
    else:
        idx = node_addresses_len - 1
    
    # check again with idx <- idx - 1
    node_addr = node_addresses[idx]
    print("check next node_addr: %s" % str(node_addr))
    
    if node_addr[0] == search_pid and node_addr[1] == search_layer_no:
        prev_size = pyd_execNodes[node_addr]['length']
        if search_start_addr < node_addr[2] + prev_size and search_start_addr + search_exec_size <= node_addr[2] + prev_size:
            return pyd_execNodes[node_addr]
            
        else:
            assert(False), "Error, Not found in array"
        
    else:
        assert(False), "Error, Not found in array"
    
#    pyd_execNode = pyd_execNodes[idx]
    assert(False), "Should not reach here"
    
# collects all transition information for each memory range, the number of each executions before reaching this range
# in pyd_execNodes = dict of the memory ranges
# in jsonData = dict of parsed json execution log
# in node_addresses = list of triple(pid, layer_no, start_addr) sorted ascending by pid, layer_no and start_addr.
# return void
# throw AssertionError if no memory range found for at least one transition
def createTransitionEdgeData(pyd_execNodes, jsonData, node_addresses):
    node_addresses_len = len(node_addresses)
    
    #pyd_execNodesPerPidLayer = splitExecNodeToPerPidLayer(pyd_execNodes)
    
    for processJson in jsonData:
        if processJson == {}:
            continue
        
        process = processJson['process']
        pid = process['pid']
        
        layers = processJson['layers']
        
        for layer in layers:
            if layer == {}:
                continue
            
            layer_no = layer['layer_no']
            
            executions = layer['executions']
            
            for execution in executions:
                if execution == {}:
                    continue
                
                executionRange = execution['execution']
                execStartAddr = executionRange["start_addr"]
                execSize = executionRange["size"]
                execNodeKey = (pid, layer_no, execStartAddr)
                tttn = findKeyOnExecNodes(pyd_execNodes, execNodeKey, node_addresses, execSize)
                
                transitions_sources = execution["transitions_sources"]
                
                for transition in transitions_sources:
                    if transition == {}:
                        continue
                    
                    source_pid = transition['pid']
                    source_layer_no = transition['layer_no']
                    source_addr = transition['from']
                    target_addr = transition['target']
                    total_trans = transition['total']
                    
                    source_addr_key = (source_pid, source_layer_no, source_addr)
                    idx = bisect.bisect_left(node_addresses, source_addr_key)
                    found = False
                    
                    print("idx = %d" % idx)
                    
                    if idx < node_addresses_len:
                        node_addr = node_addresses[idx]
                        print("node_addr: %s" % str(node_addr))
                        
                        if node_addr[0] == source_pid and node_addr[1] == source_layer_no:
                            if node_addr[2] == source_addr:
                                #incMapFromZero(pyd_execNodes[execNodeKey]['transition'], node_addr, total_trans
                                incMapFromZero(tttn['transition'], node_addr, total_trans)
                                found = True
                                
                            elif node_addr[2] > source_addr:
                                if idx == 0:
                                    # the current node address is larger than source addr
                                    assert(False), "Error, unknown transition source from source pid: %d, source layer: %d, source_addr %x in pid %d, layer %d, target_addr %x" % (source_pid, source_layer_no, source_addr, pid, layer_no, target_addr)
                                        
                                else:
                                    # check idx - 1
                                    idx -= 1
                            
                            else:
                                assert(False), "Unknown error, should not happen"
                        else:
                            idx -= 1
                            #assert(False), "Error, unknown transition source from source pid: %d, source layer: %d, source_addr %x in pid %d, layer %d, target_addr %x" % (source_pid, source_layer_no, source_addr, pid, layer_no, target_addr)
                    else:
                        idx = node_addresses_len - 1
                    
                    if not found:
                        # check again with idx <- idx - 1
                        node_addr = node_addresses[idx]
                        print("check next node_addr: %s" % str(node_addr))
                        
                        if node_addr[0] == source_pid and node_addr[1] == source_layer_no:
                            prev_size = pyd_execNodes[node_addr]['length']
                            if source_addr < node_addr[2] + prev_size:
                                #incMapFromZero(pyd_execNodes[execNodeKey]['transition'], node_addr, total_trans)
                                incMapFromZero(tttn['transition'], node_addr, total_trans)
                                
                            else:
                                assert(False), "Error, overlapping transition source from source pid: %d, source layer: %d, source_addr %x in pid %d, layer %d, target_addr %x" % (source_pid, source_layer_no, source_addr, pid, layer_no, target_addr)
                            
                        else:
                            assert(False), "Error, unknown transition source from source pid: %d, source layer: %d, source_addr %x in pid %d, layer %d, target_addr %x" % (source_pid, source_layer_no, source_addr, pid, layer_no, target_addr)

# collects all write information for each memory range, the number of each writes performed executions in this memory range
# in pyd_execNodes = dict of the memory ranges
# in jsonData = dict of parsed json execution log
# in node_addresses = list of triple(pid, layer_no, start_addr) sorted ascending by pid, layer_no and start_addr.
# return void
# throw AssertionError if no memory range found for at least one write
def createWriteEdgeData(pyd_execNodes, jsonData, node_addresses):
    node_addresses_len = len(node_addresses)
    
    #pyd_execNodesPerPidLayer = splitExecNodeToPerPidLayer(pyd_execNodes)
    
    for processJson in jsonData:
        if processJson == {}:
            continue
        
        process = processJson['process']
        pid = process['pid']
        
        layers = processJson['layers']
        
        for layer in layers:
            if layer == {}:
                continue
            
            layer_no = layer['layer_no']
            
            executions = layer['executions']
            
            for execution in executions:
                if execution == {}:
                    continue
                
                executionRange = execution['execution']
                execStartAddr = executionRange["start_addr"]
                execSize = executionRange["size"]
                execNodeKey = (pid, layer_no, execStartAddr)
                tttn = findKeyOnExecNodes(pyd_execNodes, execNodeKey, node_addresses, execSize)
                
                target_writes = execution['writes']
                for target_write in target_writes:
                    if target_write == {}:
                        continue
                    
                    target_pid = target_write['pid']
                    target_layer_no = target_write['layer_no']
                    target_addr = target_write['addr']
                    target_write_times = target_write['total']
                    
                    target_node_search_key = (target_pid, target_layer_no, target_addr)
                    idx = bisect.bisect_left(node_addresses, target_node_search_key)
                    found = False
                    
                    # for writes, no need to be strict. If the target address is not within executable ranges
                    # just ignore them
                    if idx < node_addresses_len:
                        node_addr = node_addresses[idx]
                        print("node_addr: %s" % str(node_addr))
                        
                        if node_addr[0] == target_pid and node_addr[1] == target_layer_no:
                            if node_addr[2] == target_addr:
                                incMapFromZero(tttn['writes'], node_addr, target_write_times)
                                found = True
                                
                            elif node_addr[2] > target_addr:
                                if idx == 0:
                                    # ignore result here...
                                    found = True
                                        
                                else:
                                    # check idx - 1
                                    idx -= 1
                            else:
                                assert(False), "Unknown error, should not happen"
                        else:
                            idx -= 1
                    else:
                        idx = node_addresses_len - 1
                    
                    if not found:
                        # check again with idx <- idx - 1
                        node_addr = node_addresses[idx]
                        print("check next node_addr: %s" % str(node_addr))
                        
                        if node_addr[0] == target_pid and node_addr[1] == target_layer_no:
                            prev_size = pyd_execNodes[node_addr]['length']
                            if target_addr < node_addr[2] + prev_size:
                                incMapFromZero(tttn['writes'], node_addr, target_write_times)

# creates pydot Nodes and Edges to generate the graph
# 
# in pyd_graph = pydot Dot object, pydot topmost level graph, created by pydot.Dot class
# in pyd_processBlocks = dict, the dict of pydot process Clusters
# in pyd_execNodes = dict, the dict for memory range nodes
# in pyd_layerBlocks = dict, the dict for layers clusters
# in jsonData = dict, the python dict for json input data
# return void
def createNodes(pyd_graph,  pyd_processBlocks, pyd_execNodes, pyd_layerBlocks, jsonData):
    
    lastExecMap = {}
    for processJson in jsonData:
        if processJson == {}:
            continue
        
        for lastX in processJson['last_executing_instructions']:
            if lastX == {}:
                continue
            
            last_tid = lastX['thread']
            last_addr = lastX['addr']
            last_layer_no = lastX['layer_no']
            last_insncnt = lastX['insncnt']
            
            lastExecMap[(last_layer_no, last_addr)] = True
    
    start_addr_list = []
    for wpk in pyd_execNodes:
        start_addr = wpk[2]
        start_addr_list.append(start_addr)
    
    start_addr_list.sort()
    start_addr_idx = {}
    sa_idx_n = 0
    for sa in start_addr_list:
        start_addr_idx[sa] = sa_idx_n
        sa_idx_n += 1
    
    for wpk in pyd_execNodes:
        # (processPid, layer_no, execRange['start_addr'])
        pyd_execNodeWrapper = pyd_execNodes[wpk]
        pid = wpk[0]
        layer_no = wpk[1]
        start_addr = wpk[2]
        memloc = pyd_execNodeWrapper['memloc']
        size = pyd_execNodeWrapper['length']
        #pprange = pyd_execNodeWrapper['pprange_obj']
        pprange_start = pyd_execNodeWrapper['pprange'][0]
        pprange_end = pyd_execNodeWrapper['pprange'][1]
        frames = pyd_execNodeWrapper['frames']
        pyd_layerBlock = pyd_layerBlocks[(pid, layer_no)]
        transition = pyd_execNodeWrapper['transition']
        writes = pyd_execNodeWrapper['writes']
        uniq_api_count_map = pyd_execNodeWrapper['uniq_api_count_map']
        api_group_count_map = pyd_execNodeWrapper['api_group_count_map']
        
        n_uniq_api_calls = len(uniq_api_count_map)
        n_total_api_calls = 0
        for api in uniq_api_count_map:
            n_total_api_calls += uniq_api_count_map[api]
        
        str_api_group_code = ""
        api_group_abbrev = [
            ("GetCommandLine", "C"),
            ("GetModuleHandle", "G"),
            ("GetVersion", "V"),
            ("MessageBox", "M"),
            ("Others", "O")
        ]
        
        for api in api_group_count_map:
            for ag in api_group_abbrev:
                if ag[0] in api:
                    str_api_group_code += ag[1]
        
        color = "#FFFFFF"
        
        if len(writes) == 0:
            # no writes
            # color = yellow
            color = "#FFFDA3"
        
        if len(writes) > 0:
            # color = gray
            color = "#cecece"
        
        for trk in transition:
            #(processPid, layer_no, execRange['start_addr'])
            source_pid = trk[0]
            if source_pid != pid:
                # color = green
                color = "green"
                break
        
        for lemk in lastExecMap:
            if layer_no == lemk[0] and lemk[1] >= start_addr and lemk[1] < start_addr + size:
                color = "red"
                break
        
        # xlabel won't work for nodes because it makes it very ugly
        # pos does not work for 'dot' engine.
        pyd_execNode = pydot.Node(genNodeKey(pid, layer_no, memloc, start_addr, size, pprange_start, pprange_end),
                label = genNodeLabel(memloc, start_addr, size, pprange_start, pprange_end, frames, n_uniq_api_calls, n_total_api_calls, str_api_group_code),
                #style="filled", fillcolor=color, shape="rectangle",pos="%d %d!" % (start_addr_idx[start_addr] * 200, layer_no * 2))
                style="filled", fillcolor=color, shape="rectangle")
        
        pyd_execNodeWrapper['pyd'] = pyd_execNode
        
        pyd_layerBlock.add_node(pyd_execNode)
        
    
    for k in pyd_execNodes:
        # (processPid, layer_no, execRange['start_addr'])
        wr_pyd_execNode = pyd_execNodes[k]
        target_node = wr_pyd_execNode['pyd']
        tn_layer_no = wr_pyd_execNode['layer_no']
        
        # it is possible to manipulate the layout by adding constraint = False in edge attr and rank = "same" in cluster attr
        # add Dot(rankdir='TB') for top level graph to enable ranking from Top to Bottom edges
        # for each layer, add {rank = "same"}, makes all nodes inside it have the same rank (horizontal placement)
        # add {constraint = False} for all edges that goes from bottom node (higher layer) to upper node (lower layer).
        # use 'dot' engine.
        # tested on graph2.py and it somewhat works.
        # best method is to only allow edges from node with absolute level difference 1
        # this can show what I want.
        
        # if edge uses "label", dot.exe graphviz failed with error C0000005 or "trouble in init_rank".
        # this is an old bug in graphviz.
        # change "label" to "xlabel" somehow workaround it, but the problem is that: xlabel does not change
        # layout, while if given "label", graphviz will try its best to provide good layout to make label readable,
        # while graphviz will ignore layout of xlabel and just slap it wherever available.
        for srck in wr_pyd_execNode['transition']:
            source_node = pyd_execNodes[srck]['pyd']
            sn_layer_no = pyd_execNodes[srck]['layer_no']
            
            total = wr_pyd_execNode['transition'][srck]
            
            if sn_layer_no == tn_layer_no - 1:
                pyd_graph.add_edge(pydot.Edge(source_node, target_node, color='blue', label="%d" % total))
                
            elif sn_layer_no == tn_layer_no + 1:
                pyd_graph.add_edge(pydot.Edge(source_node, target_node, color='blue', label="%d" % total, constraint = False))
                
        
        for srck in wr_pyd_execNode['writes']:
            source_node = pyd_execNodes[srck]['pyd']
            sn_layer_no = pyd_execNodes[srck]['layer_no']
            
            total = wr_pyd_execNode['writes'][srck]
            
            if sn_layer_no == tn_layer_no - 1:
                pyd_graph.add_edge(pydot.Edge(target_node, source_node, color='green', label="%d" % total, constraint = False))
                
            elif sn_layer_no == tn_layer_no + 1:
                pyd_graph.add_edge(pydot.Edge(target_node, source_node, color='green', label="%d" % total))
                
            
# main function
# return void
def main():
    if (len(sys.argv) < 2):
        print("Usage %s (dypandasok log file)" % sys.argv[0])
        exit(1)
    
    fnName = sys.argv[1]
    jsonData = ""
    
    with open(fnName) as fhLog:
        jsonData = json.load(fhLog)
    
    # digraph = directed graph
    # rankdir = the ranking direction, TB = top to bottom
    # see graphviz docs
    pyd_graph = pydot.Dot(graph_type='digraph', rankdir='TB')
    
    # key = pid, value = pydot process block cluster
    pyd_processBlocks = {}
    
    createPydProcesses(pyd_graph, pyd_processBlocks, jsonData)
    
    # key = triple(pid, layer_no, start_addr) = {
    # length: length of execution
    # pyd: pyd node object
    # memloc: string location
    # frames: integer frames
    # pprange: tuple (start, end)
    #}
    pyd_execNodes = {}
    
    # key = (pid, layer_no), value = pyd object
    pyd_layerBlocks = {}
    
    # create the execution layers and nodes
    createPydExecutionLayerNodes(pyd_graph, pyd_processBlocks, pyd_execNodes, pyd_layerBlocks, jsonData)
    
    # objects are in tuple: (processPid, layer_no, start_addr)
    # use length from pyd_execNodes to obtain the length of this execution code.
    # there shouldn't have any overlapping regions!
    node_addresses = sorted(pyd_execNodes.keys())
    node_addresses_len = len(node_addresses)
    
    checkOverlapping(node_addresses, pyd_execNodes)
    
    print("node_addresses: %s, length: %d" % (node_addresses, node_addresses_len))
    
    # connect the transition edges
    createTransitionEdgeData(pyd_execNodes, jsonData, node_addresses)
    createWriteEdgeData(pyd_execNodes, jsonData, node_addresses)
    
    # draw nodes and edges
    createNodes(pyd_graph,  pyd_processBlocks, pyd_execNodes, pyd_layerBlocks, jsonData)
    
    # graphviz prog engines:
    # 'fdp' is more actively developed, more bugs, superset of neato, but it is less manual modification
    #       then neato. fdp supports edges from cluster to cluster.
    #
    # 'neato' is more stable, less bugs but less features than fdp, 
    #       especially related to clusters. You can specify the node positions manually
    # 
    # 'dot' engine deals all of the positioning, width etc. for you (and you 
    #       cannot influence them directly!). Very convenient but sometimes the 
    #       generated graph sucks (too wide, unreadable, etc) / dot crashed
    #       Very good for generic graphs.
    #
    # Since the generated graph is very specific and structured, maybe it is better
    # to use fdp / neato here...
    #
    # After testing, it is found that 'dot' still provides better one because
    # fdp usually generated circular / square graphs
    # neato does not generated readable graph for large nodes.
    # by removing all transition and writes to layers beyond +- 1, and set all edges to layers 
    # before this constraint=False, it is possible to guide 'dot' to assign ranks to each node
    pyd_graph.write_png('%s.png' % fnName, prog = 'dot')
    
if __name__ == '__main__':
    main()
