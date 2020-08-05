#  Plugin to detect memory, hidden by PTE subversions on Linux.
#
#    Copyright (c) 2020, Frank Block, ERNW Research GmbH <fblock@ernw.de>
#
#       All rights reserved.
#
#       Redistribution and use in source and binary forms, with or without modification,
#       are permitted provided that the following conditions are met:
#
#       * Redistributions of source code must retain the above copyright notice, this
#         list of conditions and the following disclaimer.
#       * Redistributions in binary form must reproduce the above copyright notice,
#         this list of conditions and the following disclaimer in the documentation
#         and/or other materials provided with the distribution.
#       * The names of the contributors may not be used to endorse or promote products
#         derived from this software without specific prior written permission.
#
#       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#       AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#       IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#       ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#       LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#       DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#       SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#       CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#       OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#       OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""This plugin detects memory, hidden by PTE subversions on Linux.
References:
https://dfrws.org/presentation/hiding-process-memory-via-anti-forensic-techniques/
https://www.blackhat.com/us-20/briefings/schedule/index.html#hiding-process-memory-via-anti-forensic-techniques-20661
"""

import logging

from typing import List
from collections import defaultdict
from past.utils import old_div

from volatility.framework import constants, interfaces, renderers, objects, contexts, exceptions
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints
from volatility.plugins.linux import pslist
from volatility.framework.automagic import linux

vollog = logging.getLogger(__name__)

def is_tmpfs_file(file_obj):
    """We are currently concentrating on tmpfs shared memory."""
    if not file_obj or not file_obj.f_mapping:
        return False

    return (file_obj.f_mapping.host.dereference().i_mode >> 12) == 8 and \
        'tmpfs' == objects.utility.array_to_string(file_obj.get_vfsmnt().dereference().mnt_sb.dereference().s_id)


class PteSubversions(interfaces.plugins.PluginInterface):
    """This plugin implements the detection of PTE subversions on Linux.
    It can also be used to detect MAS remapping, but the comparison of
    PTEs with VMAs is more reliable."""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.BooleanRequirement(name = "dump_memory",
                                            description = "Dumps the hidden memory to files.",
                                            default = False,
                                            optional = True),
            requirements.SymbolTableRequirement(name = "vmlinux", description = "Linux kernel symbols"),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
        ]


    def run(self):
        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])

        return renderers.TreeGrid([("mapping", format_hints.Hex),
                                   ("PID", int),
                                   ("Process", str),
                                   ("vma", format_hints.Hex),
                                   ("vm_start", format_hints.Hex),
                                   ("vm_end", format_hints.Hex),
                                   ("page_diff_count", int),
                                   ("file_path", str)],
                                  self._generator(
                                      pslist.PsList.list_tasks(self.context,
                                                               self.config['primary'],
                                                               self.config['vmlinux'],
                                                               filter_func = filter_func)))


    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # page struct size
        self.PAGE_STRUCT_SIZE = None
        # offset to page struct array
        self.vmemmap_base = None
        self.PAGE_BITS = None
        self.PAGE_SIZE = None
        self.page_db = None


    def get_phys_addr_for_page(self, page):
        return (old_div((page.vol.offset - self.vmemmap_base),
                        self.PAGE_STRUCT_SIZE)) << self.PAGE_BITS


    def get_page_for_offset(self, page_offset):
        pfn = int((page_offset - self.vmemmap_base) / self.PAGE_STRUCT_SIZE)
        return self.page_db[pfn]


    def get_mapping_for_page(self, page):
        # Depending on the LSB, mapping points either to an anon_vma (LSB=1) or
        # an address_space object (LSB=0). Since we don't use the object itself
        # but are only interested in the object offset, we simply clear the LSB
        # and collect the offset.
        return int(page.unnamed_field_8.mapping) &~ 1
        
        # for future usage: code to get the actual object
        # ~ mapping_offset = page.unnamed_field_8.mapping
        # ~ if mapping_offset & 1:
            # ~ return self.context.object(
                # ~ self.config["vmlinux"] + constants.BANG + "anon_vma",
                # ~ offset = mapping_offset &~ 1,
                # ~ layer_name = self.config["primary"])
        # ~ else:
            # ~ return mapping_offset.dereference()


    # TODO This is very slow and should be replaced with PTE enumeration
    # in the future.
    def get_pages_for_vma(self, proc_layer, vma, pid):
        size = vma.vm_end - vma.vm_start
        for vaddr in range(vma.vm_start, vma.vm_end, self.PAGE_SIZE):
            self._progress_callback(((vaddr-vma.vm_start) / size) * 100,
                "Inspecting PID {:d} VMA 0x{:x}: vaddr 0x{:x}"
                .format(pid, vma.vol.offset, vaddr))
            try:
                pfn = proc_layer.translate(vaddr)[0]
            except (exceptions.InvalidAddressException):
                continue
            pfn = pfn >> self.PAGE_BITS
            
            yield (vaddr, self.page_db[pfn])


    def get_all_physical_pages(self):
        physical_pages = defaultdict(set)

        for pfn, page in enumerate(self.page_db):
            self._progress_callback(
                (pfn / self.max_pfn) * 100,
                "Inspecting PFN {:d} / {:d}".format(pfn, self.max_pfn))
            # page = self.get_page_for_pfn(pfn)
            mapping = self.get_mapping_for_page(page)
            if mapping:
                physical_pages[mapping].add(page)
                
        return physical_pages


    def get_vma_name(self, proc, vma):
        fname = ""
        if vma.vm_file:
            fname = linux.LinuxUtilities.path_for_file(self.context,
                                                       proc,
                                                       vma.vm_file)
        else:
            fname = self.is_heap_or_stack_vma(proc, vma)

        return fname


    def is_heap_or_stack_vma(self, proc, vma):
        fname = ""
        # main heap can span over 3 or more vm_area_struct structs
        if vma.vm_start <= proc.mm.start_brk < vma.vm_end or \
                (proc.mm.start_brk <= vma.vm_start and
                 vma.vm_end <= proc.mm.brk) or \
                vma.vm_start < proc.mm.brk <= vma.vm_end:
            fname = "[heap]"
        elif (vma.vm_start <= proc.mm.start_stack <= vma.vm_end):
            fname = "[stack]"
        
        return fname


    def _generator(self, procs):
        self.kernel_layer = self.context.layers['primary']
        self.PAGE_BITS = self.kernel_layer._page_size_in_bits
        self.PAGE_SIZE = 1 << self.PAGE_BITS
        self.PAGE_BITS_MASK = self.PAGE_SIZE - 1

        self.vmlinux = contexts.Module(
            self.context, self.config['vmlinux'], self.config['primary'], 0)
        self.vmemmap_base = self.context.symbol_space.get_symbol(
            self.config["vmlinux"] + constants.BANG + "vmemmap_base").address
        self.vmemmap_base = self.vmlinux.object(
            object_type = 'pointer',
            offset = self.vmemmap_base,
            subtype = self.vmlinux.get_type("pointer"))

        # getting page DB (array of page structs, describing the physical space)
        self.max_pfn = self.context.symbol_space.get_symbol(
            self.config["vmlinux"] + constants.BANG + "max_pfn").address
        self.max_pfn = int(self.vmlinux.object(object_type = 'pointer',
                                               offset = self.max_pfn))
        self.page_db = self.vmemmap_base.dereference().cast(
            "array", count = self.max_pfn,
            subtype = self.vmlinux.get_type("page"))

        self.vmemmap_base = int(self.vmemmap_base)

        page_struct_string = self.config['vmlinux'] + constants.BANG + "page"
        page_struct = self.context.symbol_space.get_type(page_struct_string)
        self.PAGE_STRUCT_SIZE = page_struct.vol.size

        # vma_mappings contains all mappings directly referenced by VMAs and
        # stores the corresponding task and VMA:   { mappingA: (proc123, VMA1) }
        #
        # page_mappings contains all mappings, gathered by resolving the virtual
        # addresses for vm_start/vm_end to a page struct instance, and the pages
        # itself: { mappingA: (page1, page2, page3, ...)} 
        all_vma_asms = {'vma_mappings': defaultdict(set),
                        'page_mappings': defaultdict(set)}

        if self.config.get('pid', None):
            vollog.warning(
                "This plugin should be run without any process filtering, "
                "as it will otherwise produce more false positives.")

        physical_pages = self.get_all_physical_pages()
        self.phys_layer = self.context.layers['memory_layer']

        for proc in procs:
            if not proc.mm:
                continue

            pid = proc.pid
            proc_layer_name = proc.add_process_layer()
            proc_layer = self.context.layers[proc_layer_name]
            vma_pages = defaultdict(dict)

            for vma in proc.mm.get_mmap_iter():

                # Used to test for PTE remapping within the same VMA, which
                # wouldn't be catched by a comparison based on mappings.
                # On the other hand, PTE remapping to another VMA/Process is
                # catched with mappings but checking for duplicate PFNs globally
                # would currently throw too many FPs (result of process forks:
                # shared heap, stack, ...). We could check for heap/stack, but
                # that wouldn't be enough and would involve identifying all
                # thread stacks and especially all VMAs belonging to the heap
                # (the [heap] VMA is not everything), which involves an analysis
                # of the heap structures and depends on the concrete
                # implementation.
                pfn_list_for_vma = list()

                # Used to compare the mappings from this vm_area_struct and the
                # mappings from the pages, pointed to by vm_start and vm_end.
                curr_vma_page_mappings = set()
                curr_vma_vma_mappings = set()

                if vma.vm_file:
                    # we are currently looking for in-memory only
                    if not is_tmpfs_file(vma.vm_file.dereference()):
                        continue
                    curr_vma_vma_mappings.add(vma.vm_file.f_mapping)

                # The list members are anon_vma_chain structures, pointing to
                # anon_vma struct instances. 
                # anon_vma: mapping for private memory and COW for shared memory
                anon_vmas = [int(x.anon_vma) for x in
                    vma.anon_vma_chain.to_list(
                        self.config["vmlinux"] + constants.BANG +
                        'anon_vma_chain', 'same_vma')]
                curr_vma_vma_mappings = curr_vma_vma_mappings.union(anon_vmas)
                for mapping in curr_vma_vma_mappings:
                    all_vma_asms['vma_mappings'][mapping].add((proc,vma))

                for vaddr, page in self.get_pages_for_vma(proc_layer, vma, pid):
                    mapping = self.get_mapping_for_page(page)
                    pfn = self.get_phys_addr_for_page(page) >> self.PAGE_BITS

                    if pfn in pfn_list_for_vma:
                        vollog.warning(
                            "Duplicate PFN for process {:d} and VMA 0x{:08x}: "
                            "vaddr 0x{:08x} with PFN {:d}. SUSPICIOUS!"
                            .format(pid, vma.vm_start, vaddr, pfn))
                    else:
                        pfn_list_for_vma.append(pfn)

                    curr_vma_page_mappings.add(mapping)
                    all_vma_asms['page_mappings'][mapping].add(page)
                    
                # There shouldn't be pages for this VMA with a mapping,
                # not part of the VMA's mappings.
                mappings_diff = curr_vma_page_mappings - curr_vma_vma_mappings
                if mappings_diff:
                    if len(mappings_diff) == 1 and mappings_diff.pop() == 0:
                        message = ("There are pages for process {:d} and "
                            "vm_start 0x{:x} which don't have any associated "
                            "mappings. While this can happen legitimately, we "
                            "can't verify that/check them for being hidden."
                            .format(pid, vma.vm_start))
                        if curr_vma_vma_mappings: 
                            vollog.warning(message)
                        else:
                            vollog.info(message)
                    else:
                        vollog.warning(
                            "Additonal anon_vma for private page on process "
                            "{:d} and vm_start 0x{:x}. Suspicious!"
                            .format(pid, vma.vm_start))

        divider_string = "Mapping 0x%x with a page diff of count of %d"
        # We are iterating over all mappings, directly referenced by the VMAs,
        # and searching for differences by comparing the pages for
        # vm_start/vm_end with the physical pages, belonging to the same
        # mapping.
        all_vma_asms_size = len(all_vma_asms['vma_mappings'].keys())
        for i, mapping in enumerate(all_vma_asms['vma_mappings'].keys()):
            self._progress_callback((i/all_vma_asms_size) * 100, 
                "Comparing pages based on mappings")

            cur_vma_pages = set([x.vol.offset for x in all_vma_asms['page_mappings'][mapping]])
            cur_phys_pages = set([x.vol.offset for x in physical_pages[mapping]])
            page_diff = cur_phys_pages ^ cur_vma_pages
            page_diff_count = len(page_diff)

            if page_diff_count > 0:
                for proc, vma in all_vma_asms['vma_mappings'][mapping]:
                    yield (0, (format_hints.Hex(mapping),
                               proc.pid,
                               utility.array_to_string(proc.comm),
                               format_hints.Hex(vma.vol.offset),
                               format_hints.Hex(vma.vm_start),
                               format_hints.Hex(vma.vm_end),
                               page_diff_count,
                               self.get_vma_name(proc, vma)))

                if self.config.get('dump_memory', True):
                    # vollog.info("Starting dump...")
                    procs_vmas_string = "_".join(
                        [str(proc.pid) + "-" + hex(vma.vm_start) for proc, vma
                            in all_vma_asms['vma_mappings'][mapping]])
                    
                    for page_addr in page_diff:
                        page = self.get_page_for_offset(page_addr)
                        phys_addr = self.get_phys_addr_for_page(page)
                        pfn = phys_addr >> self.PAGE_BITS
                        filename = (
                            "mapping.0x{:08x}_procs-vmas.{:s}_pfn.0x{:08x}.dmp"
                            .format(mapping, procs_vmas_string, pfn))

                        filedumper = interfaces.plugins.FileInterface(filename)
                        filedumper.data.write(
                            self.phys_layer.read(phys_addr, self.PAGE_SIZE))
                        self.produce_file(filedumper)
                        # vollog.info("Dumped content to {0}\n", filename)
