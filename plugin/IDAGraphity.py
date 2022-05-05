# IdaGraphity - Generate a graph view of a given the binary
# Guillaume Orlando - 01/05/2022

# Global Plugin Management Variables
PLUGIN_NAME = "IDAGraphity"
PLUGIN_DIR = "C:\\Tools\\IDA 7.7\\IDA 7.7\\plugins\\IDAGraphity"
PLUGIN_HOTKEY = 'Alt+²'
VERSION = '0.0.1'

import idc
import idautils
import idaapi
from ida_kernwin import Form

import os
import sys
import time
import json
import webbrowser
from os import path

# Check if the IDA / Python versions are compatible with our plugin
major, minor = map(int, idaapi.get_kernel_version().split("."))
assert (major > 6),"ERROR: IDAGraphity plugin requires IDA v7+"
assert (sys.version_info >= (3, 5)), "ERROR: IDAGraphity plugin requires Python 3.5"

# Class that handle the modal form when accesing the configuration menu in the Edit -> Plugin -> IDAGraphity
class IdaGraphity_Form(Form):
    def __init__(self):
        self.invert = False
        Form.__init__(self, r"""STARTITEM {id:rNormal}
BUTTON YES* Generate
BUTTON CANCEL Cancel
IDAGraphity
            IDAGraphity: An interactive binary visualisation plugin.
            {FormChangeCb}
            <#Hint2#:{iColor1}>Regular functions base color 
            <#Hint2#:{iColor2}>Library functions base color 
            <#Hint2#:{iColor3}>External Symbols base color  
            <#Hint2#:{iColor4}>Background Color             

            <##Reset Default Colors:{iButton3}>

            <##Node Visibility##Show Library Functions:{rShowLib}>
            <Show External API Functions:{rShowApi}>
            <Display Nodes Names:{rDisplayName}>
            <Remove Orphan Nodes:{rRemoveOrphan}>
            <Display Data on Hoover:{rHoover}>
            <Nodes interactions (drag & move):{rDrag}>{cGroup1}>

            <#Select a file to open#FLARE capa integration:{iFileOpen}>
            <#Hint1#Include functions starting by  :{iStr1}>
            <#Hint1#Blacklist functions starting by:{iStr2}>

            A browser will be open to display the result after the graph generation.""", {
            'iColor1': Form.ColorInput(),
            'iColor2': Form.ColorInput(),
            'iColor3': Form.ColorInput(),
            'iColor4': Form.ColorInput(),
            'iStr1': Form.StringInput(swidth=20),
            'iStr2': Form.StringInput(swidth=20),
            'iButton3': Form.ButtonInput(self.OnResetColor),
            'iFileOpen': Form.FileInput(swidth=20, open=True),
            'cGroup1': Form.ChkGroupControl(("rShowLib", "rShowApi", "rNormal", "rRemoveOrphan", "rDrag", "rDisplayName", "rHoover")),
            'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
        })

    def OnResetColor(self, code=0):
        print("Color Reset")
        self.SetControlValue(self.iColor1, 0xe4c3aa)
        self.SetControlValue(self.iColor2, 0xc9e5d0)
        self.SetControlValue(self.iColor3, 0xdcd1ea)
        self.SetControlValue(self.iColor4, 0xffffff)

    def OnFormChange(self, fid):
        return 1

# Deal with the weird way IDA output color code.
def reverse_hex_color_code(val):
    value = bytes.fromhex(hex(val)[2:])
    value = value[::-1]
    return int('0x' + bytes.hex(value), 16)

# Construct and open the modal form of the plugin configuration option
def IdaGraphity_Configuration_Plugin():
    global f
    use_capa = False
    f = IdaGraphity_Form()
    f.Compile()
    f.iColor1.value = 0xe4c3aa
    f.iColor2.value = 0xc9e5d0
    f.iColor3.value = 0xdcd1ea
    f.iColor4.value = 0xffffff
    f.rShowLib.checked = True
    f.rShowApi.checked = True
    f.rDisplayName.checked = True
    f.rHoover.checked = True
    f.rRemoveOrphan.checked = False
    f.rDrag.checked = False
    f.iFileOpen.value = "capa_plugin_result.json"
    f.iStr1.value = ""
    f.iStr2.value = ""
    ok = f.Execute()

    if ok == 1:
        if (path.exists(f.iFileOpen.value)):
            use_capa = f.iFileOpen.value
        generate_and_render( 
            reverse_hex_color_code(f.iColor1.value), 
            reverse_hex_color_code(f.iColor2.value), 
            reverse_hex_color_code(f.iColor3.value), 
            reverse_hex_color_code(f.iColor4.value),
            f.rShowLib.checked,
            f.rShowApi.checked,
            f.rRemoveOrphan.checked,
            f.rHoover.checked,
            f.rDrag.checked,
            f.rDisplayName.checked,
            use_capa,
            f.iStr1.value,
            f.iStr2.value
        )
    else:
        print("Cancel")

    f.Free()

# Register the plugin into IDA
class IDAGraphity_Plugin_t(idaapi.plugin_t):
    comment = "IDAGraphity - Interactive Function Graph Builder"
    help = ""
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ''
    flags = idaapi.PLUGIN_KEEP
    terminated = False

    def init(self):
        print('IDaGraphity Plugin Loaded')
        #load_settings()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        entry()

    def term(self):
        if self.terminated:
            return
        self.terminated = True

# Plugin related data initialisation for the first run
def init_first_run():
    if path.isdir(PLUGIN_DIR):
        pass
    else:
        print('IDAGraphity plugin: No PLUGIN_DIR found, initializing ...')
        os.mkdir(PLUGIN_DIR)
    return

# Get a string value by reference from the given address.
def get_string(address):
    type = idc.get_str_type(address)

    if type != None:
        str_value = idc.get_strlit_contents(address, -1, type)
        return str_value

    return None

# Get a list of callee function from a given frame.
def get_callee_functions(address, end):
    api_count = 0
    content = []

    while address != end:
        if address == idaapi.BADADDR:
            break

        ins = idc.print_insn_mnem(address)

        if ins == "call":
            operand = idc.get_operand_value(address, 0)

            if operand > 10:
                # Not a call to a register
                f_name = idc.get_func_name(operand)

                if f_name:
                    content.append([ hex(address), str(f_name) ])
                    api_count += 1
        address = idc.next_head(address)

    return content, api_count

# Get the calling convention type of the given function.
def get_calling_convention(f_address):
    f_def = idc.get_type(f_address)

    if f_def == None:
        return ""

    try:
        call_conv = f_def.split('__')[1].split('(')[0]
    except:
        call_conv = ""

    return str(call_conv)

# Get the number of instructions in the given frame.
def get_function_content(start, end):
    size = 0
    str_count = 0
    address = start
    content = []
    while address != end:

        if address == idaapi.BADADDR:
            break
        # Search for strings
        refs = idautils.DataRefsFrom(address)

        for ref in refs:
            str_value = get_string(ref)

            if str_value != None:
                content.append([ hex(ref), str(str_value) ])
                str_count += 1
        size += 1
        address = idc.next_head(address)

    return size, str_count, content

# Wrapper for the node object creation.
def generate_function_node(f_name, f_address, dispaly_lib, dispaly_api):
    func_type = "regular"
    size, str_number, content = get_function_content(f_address, idc.find_func_end(f_address))
    call_conv = get_calling_convention(f_address)
    api_content, api_count = get_callee_functions(f_address, idc.find_func_end(f_address))
    content += api_content

    node = { 
	   "functiontype" : "",
	   "calltype" : str(call_conv),
       "capa_rule" : "",
	   "id" : str(f_name),
	   "size" : int(size),
	   "apicount" : int(api_count),
	   "is_ep" : 0,
	   "stringcount" : int(str_number),
	   "content" : content
    }

    return node, api_content

# Complete the links object with proper target function id from the complete node object.
def gen_link_nodes(br_links, node_array):
    rm_array = []

    for link in br_links:
        target = link['target']
        node_index = next((index for (index, d) in enumerate(node_array) if d['id'] == target ), None)
        link['target'] = node_index

        if node_index == None:
            rm_array.append(link)

    for broken in rm_array:
        br_links.remove(broken)

    return br_links

# Generate a graph object with node list and incomplete links.
def generate_graph(dispaly_lib, dispaly_api, blacklist=[], prefix="", ban=""):
    links = []
    nodes = []
    node_index = -1
    use_whitelist = False
    use_banlist = False
    if len(prefix):
        use_whitelist = True
    if len(ban):
        use_banlist = True
    for function_ea in idautils.Functions():
        f_name = idc.get_func_name(function_ea)

        if use_whitelist:
            if str(prefix) not in str(f_name):
                continue

        if use_banlist:
            if str(ban) in str(f_name):
                continue

        if f_name not in blacklist:
            f_node, link_dest = generate_function_node(f_name, function_ea, dispaly_lib, dispaly_api)
            func = idaapi.get_func(function_ea)

            if func.flags & idaapi.FUNC_LIB:
                f_node['functiontype'] = "library_function"
                if not dispaly_lib:
                    continue

            elif func.flags & idaapi.FUNC_THUNK:
                f_node['functiontype'] = "external_api"
                if not dispaly_api:
                    continue

            node_index += 1
            nodes.append(f_node)
            if len(link_dest) > 0:
                for dest_addr, dest_link in link_dest:
                    links.append({
                        'pos': f_node['id'], 
                        'source': node_index, 
                        'target': str(dest_link) 
                    })

    return nodes, links

# Save the constructed json object on disk.
def save_js_data(fname, dump):
    with open(fname, 'w') as f:
        f.write(dump)    
    return

# Open the web browser to start the rendering.
def init_server():
    webbrowser.open('file:///%s/index.html' % PLUGIN_DIR)
    return

# Return a list of orphan nodes from the (still imcomplete) graph object.
def remove_orphan_nodes(links, nodes):
    orphan_nodes = []

    for node in nodes:
        n_id = node['id']
        is_orphan_content = True

        for node_target in nodes:
            node_content = node_target['content']
            if len(node_content):
                if any(n_id in sub for sub in node_target['content']):
                    is_orphan_content = False
                    break

        is_orphan_link = True
        if any(sub['pos'] == n_id for sub in links):
            is_orphan_link = False

        if is_orphan_link and is_orphan_content:
            orphan_nodes.append(n_id)

    return orphan_nodes

# Populate the nodes dataset with the FLARE's capa rule engine
def add_capa_rules(use_capa, nodes):
    if not use_capa:
        return nodes

    capa_r = []
    with open(use_capa, 'r') as f:
        data = json.load(f)

    r = data['rules']
    for rule_name in r:
        details = data['rules'][rule_name]['matches']
        meta = data['rules'][rule_name]['meta']

        rule = ''
        if len(meta['att&ck']):
            rule = meta['att&ck'][0]['technique'].title()
        elif len(meta['mbc']):
            rule = meta['mbc'][0]['behavior'].title()
        else:
            if meta['name'] != 'contain loop':
                rule = meta['name'].title()

        for addr in details:
            if len(rule):
                f_name = idc.get_func_name(int(addr, 10))
                capa_r.append({'func': f_name, 'rule': rule})

    for entry in capa_r:
        target_function = entry['func']
        target_rule = entry['rule']

        for node_entry in nodes:
            if node_entry['id'] == target_function:
                node_entry['capa_rule'] += str(target_rule) + ";"

    return nodes

# Wrapper for the graph generation. Custom colors are passed as arguments fromthe modal.
def generate_and_render(
        func1_color, 
        func2_color, 
        func3_color, 
        background_color, 
        dispaly_lib=True, 
        display_api=True, 
        remove_orphan=False,
        hoover=True,
        DragNodes=False,
        display_name=True,
        use_capa=False,
        prefix="",
        ban=""
    ):
    start_time = time.time()

    config = {
        "color1": func1_color,
        "color2": func2_color,
        "color3": func3_color,
        "background": background_color,
        "drag" : DragNodes,
        "node_name" : display_name,
        "capa" : bool(use_capa),
        "hoover" : hoover
    }

    fname = PLUGIN_DIR + '\\d3.json'
    print('-----------------------------------------------------------------------------------------')
    print('IDAGraphity plugin: FLARE capa plugin binding: %s' % str(use_capa))
    nodes, br_links = generate_graph(dispaly_lib, display_api, [], prefix, ban)
    print('IDAGraphity plugin: %d Nodes created' % len(nodes))

    if remove_orphan:
        orphan_nodes = remove_orphan_nodes(br_links, nodes)
        nodes, br_links = generate_graph(dispaly_lib, display_api, orphan_nodes, prefix, ban)

    links = gen_link_nodes(br_links, nodes)
    print('IDAGraphity plugin: %d Links created' % len(links))
    try:
        nodes = add_capa_rules(use_capa, nodes)
    except:
        print('IDAGraphity plugin: Invalid capa json file provided, unpredictable graph result ...')
    js_dump = json.dumps({
        'config': config,
        'links' : links,
        'nodes' : nodes
    })

    save_js_data(fname, js_dump)
    print('IDAGraphity plugin: Object saved under "%s\\%s"' % (PLUGIN_DIR, fname))
    print("IDAGraphity plugin: Work done in %s seconds" % (time.time() - start_time))
    init_server()

    return

# Plugin entrypoint.
def entry():
    IdaGraphity_Configuration_Plugin()
    return

# Plugin auto entrypoint
def PLUGIN_ENTRY():
    return IDAGraphity_Plugin_t()
