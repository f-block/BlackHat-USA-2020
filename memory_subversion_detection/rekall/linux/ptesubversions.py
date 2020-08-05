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

from collections import defaultdict
from rekall.plugins import core
from rekall.plugins.linux import common
from rekall.plugins.linux.hidden_shmem import is_tmpfs_file

class PteSubversionsLinux(core.DirectoryDumperMixin, common.LinProcessFilter):
    """This plugin implements the detection of PTE subversions on Linux.
    It can also be used to detect MAS remapping, but the comparison of
    PTEs with VMAs is more reliable."""

    name = "ptesubversions"
    dump_dir_optional = True
    default_dump_dir = None

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="proc", width=6),
        dict(name='vma', style="address", width=16),
        dict(name="flags", width=8),
        dict(name='vm_start', style="address", width=16),
        dict(name='vm_end', style="address", width=16),
        dict(name='mapping', style="address", width=16),
        dict(name='file_path')
    ]


    def __init__(self, *args, **kwargs):
        super(PteSubversionsLinux, self).__init__(*args, **kwargs)
        # page struct size
        self.PAGE_STRUCT_SIZE = self.session.profile.page().obj_size
        self.PAGE_SIZE = self.session.kernel_address_space.PAGE_SIZE
        self.PAGE_BITS = self.PAGE_BITS = self.PAGE_SIZE.bit_length() - 1
        self.max_pfn = self.session.profile.get_constant_object("max_pfn",
                                                                "Pointer").v()
        # getting page DB (array of page structs, describing the physical space)
        self.page_db = self.session.profile.get_constant_object(
            "vmemmap_base",
            "Pointer",
            target_args=dict(
                target="Array",
                target_args=dict(
                    target='page',
                    count=self.max_pfn)))

    # TODO This is very slow and vulnerable to MAS remapping, and should be
    # replaced by enumerating page tables in the future.
    def get_pages_for_vma(self, proc_as, vma, pid):
        for vaddr in range(vma.vm_start, vma.vm_end, self.PAGE_SIZE):
            self.session.report_progress(
                "Inspecting vaddr 0x%08x for VMA 0x%08x for Pid %d",
                vaddr, vma.v(), pid)
            phys_offset = proc_as.vtop(vaddr)
            if not isinstance(phys_offset, int):
                continue
                
            pfn = phys_offset >> self.PAGE_BITS
            yield (vaddr, self.page_db[pfn])


    def get_all_physical_pages(self):
        physical_pages = defaultdict(set)

        for pfn, page in enumerate(self.page_db):
            self.session.report_progress(
                "Inspecting PFN %d / %d", pfn, self.max_pfn)
            mapping = page.get_mapping()
            if mapping:
                physical_pages[mapping.v()].add(page.v())

        return physical_pages


    def get_vma_name(self, proc, vma):
        fname = ""
        if vma.vm_file:
            fname = proc.get_path(vma.vm_file)
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


    def collect(self):
        cc = self.session.plugins.cc()
        # vma_mappings contains all mappings directly referenced by VMAs and
        # stores the corresponding proc and VMA:   { mappingA: (proc123, VMA1) }
        #
        # page_mappings contains all mappings, gathered by resolving the virtual
        # addresses for vm_start/vm_end to a page struct instance, and the pages
        # itself: { mappingA: (page1, page2, page3, ...)} 
        all_vma_asms = {'vma_mappings': defaultdict(set),
                         'page_mappings': defaultdict(set)}

        if self.filtering_requested:
            self.session.logging.warning(
                "This plugin should be run without any process filtering, "
                "as it will otherwise produce more false positives.")

        physical_pages = self.get_all_physical_pages()

        for proc in self.filter_processes():
            if not proc.mm.dereference():
                continue

            cc.SwitchProcessContext(proc)
            pid = proc.pid
            proc_as = proc.get_process_address_space()
            vma_pages = defaultdict(dict)
            
            for vma in proc.mm.mmap.walk_list("vm_next"):
                
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
                anon_vmas = set([x.anon_vma.deref() for x in 
                    vma.anon_vma_chain.list_of_type("anon_vma_chain",
                                                    "same_vma")])
                curr_vma_vma_mappings = curr_vma_vma_mappings.union(anon_vmas)
                for mapping in curr_vma_vma_mappings:
                    all_vma_asms['vma_mappings'][mapping.v()].add((proc,vma))

                for vaddr, page in self.get_pages_for_vma(proc_as, vma, pid):
                    mapping = page.get_mapping()
                    pfn = page.physical_offset() >> self.PAGE_BITS
                    if pfn in pfn_list_for_vma:
                        self.session.logging.warning(
                            "Duplicate PFN for process {:d} and VMA 0x{:08x}: "
                            "vaddr 0x{:08x} with PFN {:d}. SUSPICIOUS!"
                            .format(pid, vma.vm_start, vaddr, pfn))
                    else:
                        pfn_list_for_vma.append(pfn)

                    curr_vma_page_mappings.add(mapping)
                    all_vma_asms['page_mappings'][mapping.v()].add(page.v())

                # There shouldn't be pages for this VMA with a mapping,
                # not part of the VMA's mappings.
                mappings_diff = curr_vma_page_mappings - curr_vma_vma_mappings
                if mappings_diff:
                    if len(mappings_diff) == 1 and mappings_diff.pop().v() == 0:
                        message = ("There are pages for process {:d} and "
                            "vm_start 0x{:x} which don't have any associated "
                            "mappings. While this can happen legitimately, we "
                            "can't verify that/check them for being hidden."
                            .format(pid, vma.vm_start))
                        if curr_vma_vma_mappings: 
                            self.session.logging.warning(message)
                        else:
                            self.session.logging.info(message)
                    else:
                        self.session.logging.warning(
                            "Additonal anon_vma for private page on process "
                            "{:d} and vm_start 0x{:x}. Suspicious!"
                            .format(pid, vma.vm_start))

        divider_string = "Mapping 0x%x with a page diff of count of %d"
        # We are iterating over all mappings, directly referenced by the VMAs,
        # and searching for differences by comparing the pages for
        # vm_start/vm_end with the physical pages, belonging to the same
        # mapping.
        for mapping in all_vma_asms['vma_mappings'].keys():
            self.session.report_progress(
                "Comparing pages based on mappings: 0x%08X", mapping)

            cur_vma_pages = all_vma_asms['page_mappings'][mapping]
            cur_phys_pages = physical_pages[mapping]
            page_diff = cur_phys_pages ^ cur_vma_pages
            page_diff_count = len(page_diff)

            if page_diff_count > 0:
                yield dict(divider=divider_string %
                                   (mapping, page_diff_count))
                for proc, vma in all_vma_asms['vma_mappings'][mapping]:
                    yield dict(proc=proc.pid,
                               vma=vma,
                               flags=vma.vm_flags,
                               vm_start=vma.vm_start,
                               vm_end=vma.vm_end,
                               mapping=mapping,
                               file_path=self.get_vma_name(proc,vma))

                # We are only dumping the diffing pages
                if self.dump_dir:
                    renderer = self.session.GetRenderer()
                    procs_vmas_string = "_".join(
                        [str(proc.pid) + "-" + hex(vma.vm_start) for proc, vma
                         in all_vma_asms['vma_mappings'][mapping]])
                    
                    for page_addr in page_diff:
                        page = self.session.profile.page(offset=page_addr)
                        phys_offset = page.physical_offset()
                        pfn = phys_offset >> self.PAGE_BITS
                        filename = (
                            "mapping.0x{:08x}_procs-vmas.{:s}_pfn.0x{:08x}.dmp"
                            .format(mapping, procs_vmas_string, pfn))

                        with renderer.open(directory=self.dump_dir,
                                        filename=filename,
                                        mode='wb') as fd:
                            fd.write(self.session.physical_address_space.read(
                                phys_offset, self.PAGE_SIZE))
                            renderer.format("Dumped content to {0}/{1}\n",
                                            self.dump_dir, filename)

