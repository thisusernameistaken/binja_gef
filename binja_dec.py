from binaryninja import BinaryViewType
import gdb

class BinjaCTX:

    def __init__(self):
        self.bvs = {}
        self.bv = None
        self.last_index = None

    def _get_map(self):
        addr = lookup_address(current_arch.pc)
        if not addr.valid:
            return
        section = addr.section
        base = section.page_start
        info = addr.info
        f_name = section.path
        vmmap = get_process_maps()
        base_address = [x.page_start for x in vmmap if x.realpath == f_name][0]
        if not f_name in self.bvs.keys():
            bv = BinaryViewType.get_view_of_file_with_options(f_name,options={"analysis.mode":"controlFlow","loader.imageBase":base_address})
            self.bvs[f_name] = bv
            self.bv = bv
        else:
            self.bv = self.bvs[f_name]

    def _decompile(self):
        if self.bv == None:
            file_name = gdb.current_progspace().filename
            self.bv = BinaryViewType.get_view_of_file(file_name)


    def display_pane(self):
        addr = current_arch.pc
        cf = self.bv.get_functions_containing(addr)[0]
        if cf.analysis_skipped:
            cf.analysis_skipped = False
            self.bv.update_analysis_and_wait()
            self.last_index = 0
        hlil = cf.get_llil_at(addr).hlil
        if hlil == None:
            if self.last_index == None:
                self.last_index = 0
            hlil_index = self.last_index
        else:
            hlil_index = hlil.instr_index
        self.last_index = hlil_index

        past_lines_color = get_gef_setting("theme.old_context")
        nb_lines = get_gef_setting("context.nb_lines_code")
        cur_line_color = get_gef_setting("theme.source_current_line")

        gef_print(f"{hex(cf.start)}: {cf.function_type.get_string_before_name()} {cf.name}{cf.function_type.get_string_after_name()}")
        for x in range(hlil_index-1,hlil_index-3,-1)[::-1]:
            if x >= 0:
                prev_hlil = cf.hlil[x]
                prev_hlil_str = str(cf.hlil).split("\n")[x]
                gef_print(Color.colorify(f"\t{x}. {hex(prev_hlil.address)}: {prev_hlil_str}",past_lines_color))
        instr = str(cf.hlil).split('\n')[hlil_index]
        gef_print(Color.colorify(f"    ➤\t{hlil_index}. {hex(addr)}: {instr}",cur_line_color))
        for x in range(hlil_index+1,hlil_index+5):
            try:
                next_hlil = cf.hlil[x]
                next_hlil_str = str(cf.hlil).split("\n")[x]
                gef_print(f"\t{x}. {hex(next_hlil.address)}: {next_hlil_str}")
            except:
                pass

    def title(self):
        #self._decompile()
        self._get_map()
        return f"Binja HLIL"
    

class BinjaDec(GenericCommand):
    """ Binja """
    _cmdline_ = "binjadec"
    _syntax_  = "{:s}".format(_cmdline_)
    
    def do_invoke(self,argv):
        print("binja")
        print(self.bv)
        return

#register_external_command(BinjaDec())
binja_ctx = BinjaCTX()
register_external_context_pane("HLIL", binja_ctx.display_pane, binja_ctx.title)
