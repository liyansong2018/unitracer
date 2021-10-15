# -- coding:utf-8 --

from idaapi import *
from idc import *
import ida_kernwin
import re

# 1) Create the handler class
class MyHandler(idaapi.action_handler_t):
    
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    
    # action when invoked.
    def activate(self, ctx):
        clear()
        print("clean up complete!")
        return 1
    
    # this action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# 2) Describe the action
action_desc = idaapi.action_desc_t(
    'my:action',    # The action name. This acts like an ID and must be unique
    'clear basic block color',   # The action text.
    MyHandler(),   # The action handler.
    'Ctrl+H',      # Optional: the action shortcut
    'clear bb',  # Optional: the action tooltip (available in menus/toolbar)
    199)           # Optional: the action icon (shows when in menus/toolbars)

# 3) Register the action
idaapi.register_action(action_desc)


class ColoringBB():
    """Color for basic block
    """
    flowchart = False 
    tgt_ea = 0 
    startea = 0 
    endea = 0 
    addr_fc = 0

    def __init__(self, addr_fc):
        self._set_fc_address(addr_fc)
        self._set_flowchart()

    def _set_fc_address(self, addr_fc):
        self.addr_fc = addr_fc 

    def _set_flowchart(self):
        f = idaapi.get_func(self.addr_fc)
        self.flowchart = idaapi.FlowChart(f)

    def coloring_bb(self, addr, color):
        self._set_bb_range(addr)
        for addr in range(self.startea, self.endea):
            idc.set_color(addr, idc.CIC_ITEM, color)     # color: olive
            
    def get_flowchart(self):
        return self.flowchart

    def _set_bb_range(self, addr):
        for block in self.flowchart:
            if block.start_ea <= addr and block.end_ea > addr:
                self.startea, self.endea = block.start_ea, block.end_ea
                break


def obtain_addr_form_file(file_name):
    '''
    description: read address from file
    param {file name} file_name
    return {address list}
    '''
    ea_list = []
    with open(file_name, "r") as f:
        while True:
            line = f.readline()
            if not line:
                break
            
            ret = re.search(r'\baddr=0x[0-9a-fA-F]+\b', line)
            if ret:
                ea_list.append(ret.group().split("=")[1])

    return ea_list


def trace_color():
    '''
    description: set color for basic block
    param {*}
    return {*}
    '''
    print(">>> ----- start tracking function ----- >>>")
    for segea in Segments():
        previous_func = ""
        for ea in ea_trace_list:
            for funcea in Functions(segea, get_segm_end(segea)):
                start_ea = idc.get_func_attr(funcea, FUNCATTR_START)
                end_ea = idc.get_func_attr(funcea, FUNCATTR_END)
                cb = ColoringBB(funcea)
                
                ea_int =  int(ea, 16)
                if start_ea <= ea_int and end_ea >= ea_int:
                    # call stack
                    func = idc.get_func_name(funcea)
                    if func != previous_func:
                        print(">>> " + func)
                    previous_func = func
                    # color the block
                    cb.coloring_bb(ea_int, 0x8f8080)          
                    break
	
def clear():
    '''
    description: clear color for basic block
    param {*}
    return {*}
    '''

    for segea in Segments():
        for funcea in Functions(segea, get_segm_end(segea)):
            cb = ColoringBB(funcea)
            for block in cb.get_flowchart():
                cb.coloring_bb(block.start_ea, 0xffffffff) 


if __name__ == "__main__":
    trace_file =  ask_file(1, ".txt", "Open address recorded（打开Unicorn记录的地址）")
    ea_trace_list = obtain_addr_form_file(trace_file)
    trace_color()