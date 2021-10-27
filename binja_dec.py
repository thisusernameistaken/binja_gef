from sys import prefix
from binaryninja import BinaryViewType
import gdb

class BinjaCTX:

    def __init__(self):
        self.bvs = {}
        self.bv = None
        self.last_index = None
        self.follow_libs = False
        # use on memory

    def _get_map(self):
        addr = lookup_address(current_arch.pc)
        if not addr.valid:
            return
        section = addr.section
        f_name = section.path
        vmmap = get_process_maps()
        base_address = [x.page_start for x in vmmap if x.realpath == f_name][0]
        if not f_name in self.bvs.keys() and (self.follow_libs or len(self.bvs)<1):
            bv = BinaryViewType.get_view_of_file_with_options(f_name,options={"analysis.mode":"controlFlow","loader.imageBase":base_address})
            self.bvs[f_name] = bv
            self.bv = bv
        elif not f_name in self.bvs.keys():
            self.bv = None
        else:
            self.bv = self.bvs[f_name]

    def _decompile(self):
        if self.bv == None:
            file_name = gdb.current_progspace().filename
            self.bv = BinaryViewType.get_view_of_file(file_name)


    def display_pane(self):
        addr = current_arch.pc
        l_addr = lookup_address(current_arch.pc)
        if not l_addr.valid:
            return
        section = l_addr.section
        f_name = section.path
        if self.bv == None:
            err(f"{f_name} has not been loaded. Either enable `bndb-follow-libs` or load the library with `bndb load`")
            return
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

        # function sig
        gef_print(f"{hex(cf.start)}: {cf.function_type.get_string_before_name()} {cf.name}{cf.function_type.get_string_after_name()}")
        # before
        for x in range(hlil_index-1,hlil_index-4,-1)[::-1]:
            if x >= 0:
                prev_hlil = cf.hlil[x]
                prev_hlil_str = str(cf.hlil).split("\n")[x]
                gef_print(Color.colorify(f"\t{x+1}. {hex(prev_hlil.address)}: {prev_hlil_str}",past_lines_color))
        # current
        instr = str(cf.hlil).split('\n')[hlil_index]
        gef_print(Color.colorify(f"     →\t{hlil_index+1}. {hex(addr)}: {instr}",cur_line_color))
        # After
        for x in range(hlil_index+1,hlil_index+5):
            try:
                next_hlil = cf.hlil[x]
                next_hlil_str = str(cf.hlil).split("\n")[x]
                gef_print(f"\t{x+1}. {hex(next_hlil.address)}: {next_hlil_str}")
            except:
                pass

    def title(self):
        #self._decompile()
        self._get_map()
        return f"Binja HLIL"

binja_ctx = BinjaCTX()

class BinjaBNDB(GenericCommand):
    """ Binja bndb"""
    _cmdline_ = "bndb"
    _syntax_  = "{:s} (display|load|follow-libs)".format(_cmdline_)
    
    def __init__(self):
        super().__init__(prefix=True)

    def do_invoke(self,argv):
        gef_print(str(binja_ctx.bvs))
        return

class BinjaBNDBFollowLib(GenericCommand):
    """ Binja display bndb"""
    _cmdline_ = "bndb follow-libs"
    _syntax_  = "{:s}".format(_cmdline_)
    
    def __init__(self):
        super().__init__()

    def do_invoke(self,argv):
        binja_ctx.follow_libs = not binja_ctx.follow_libs
        gef_print(f"Binja Follow Libs: {str(binja_ctx.follow_libs)}")
        return

class BinjaBNDBDisplay(GenericCommand):
    """ Binja display bndb"""
    _cmdline_ = "bndb display"
    _syntax_  = "{:s}".format(_cmdline_)
    
    def __init__(self):
        super().__init__()

    def do_invoke(self,argv):
        gef_print(str(binja_ctx.bvs))
        return

class BinjaBNDBLoad(GenericCommand):
    """ Binja load bndb"""
    _cmdline_ = "bndb load"
    _syntax_  = "{:s} BNDB [PATH]".format(_cmdline_)
    
    def __init__(self):
        super().__init__()

    def do_invoke(self,argv):
        try:
            if len(argv) == 1:
                print(f"Loading bndb: {argv[0]}")
                vmmap = get_process_maps()
                addr = lookup_address(current_arch.pc)
                if not addr.valid:
                    return
                section = addr.section
                f_name = section.path 
                base_address = [x.page_start for x in vmmap if x.realpath == f_name][0]
                # bv = BinaryViewType.get_view_of_file_with_options(argv[0],options={"loader.imageBase":base_address})
                bv = BinaryViewType.get_view_of_file(argv[0]).rebase(base_address)
                bv.update_analysis()
                binja_ctx.bvs[f_name] = bv 
            else:
                print(f"Loading bndb: {argv[0]} for {argv[1]}")
                vmmap = get_process_maps()
                base_address = [x.page_start for x in vmmap if x.realpath == argv[1]][0]
                bv = BinaryViewType.get_view_of_file(argv[0]).rebase(base_address)
                bv.update_analysis()
                binja_ctx.bvs[argv[1]] = bv 
            return
        except:
            self.usage()

register_external_command(BinjaBNDB())
register_external_command(BinjaBNDBDisplay())
register_external_command(BinjaBNDBLoad())
register_external_command(BinjaBNDBFollowLib())
register_external_context_pane("HLIL", binja_ctx.display_pane, binja_ctx.title)
