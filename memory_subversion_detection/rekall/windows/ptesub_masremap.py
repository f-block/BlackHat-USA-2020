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

"""This plugin implements the detection of PTE subversions and MAS remapping
on Windows.
References:
https://dfrws.org/presentation/hiding-process-memory-via-anti-forensic-techniques/
https://www.blackhat.com/us-20/briefings/schedule/index.html#hiding-process-memory-via-anti-forensic-techniques-20661
"""

from rekall.plugins import core
from rekall.plugins.windows.pte_enumerator import PteEnumerator
from rekall.plugins.addrspaces.intel import DescriptorCollection
from rekall.plugins.windows.pagefile import WindowsDTBDescriptor
from rekall.plugins.addrspaces.intel import VirtualAddressDescriptor

class PteSubMasRemapDet(core.DirectoryDumperMixin, PteEnumerator):
    """This plugin implements the detection of PTE subversions and 
    MAS remapping on Windows."""

    name = "ptesub_masremap"
    dump_dir_optional = True
    default_dump_dir = None

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="proc", width=12),
        dict(name="vaddr", width=12, style="address"),
        dict(name="pfn", width=12, style="address"),
        dict(name="pte_value", width=24, style="address"),
        dict(name="orphaned_page", width=16),
        dict(name="dup_pfn", width=16),
        dict(name="dup_pte_ptr", width=16),
        dict(name="pte_ptr_diff", width=16),
        dict(name="zero_pte", width=16)
    ]
    
    __args = [
        dict(name='test_only_orphaned_pages', type='Boolean', default=False,
             help=("Only test pages for not belonging to any VAD (detects "
                   "MAS remapping)."))
    ]


    def __init__(self, **kwargs):
        super(PteSubMasRemapDet, self).__init__(**kwargs)
        if not self.session.profile.metadata("arch") == 'AMD64':
            raise plugin.PluginError("Only x64 is currently supported.")
        elif self.session.profile.metadata("major", 0) < 10:
            raise plugin.PluginError(
                "Only Windows 10 is currently supported.")
        self.ptov_plugin = self.session.plugins.ptov()
        self.pte_addrs = dict()


    def _get_pid_and_vaddr(self, pfn):
        pid = -1
        vaddr = 0
        coll = DescriptorCollection(self.session)
        self.ptov_plugin.ptov(coll, pfn<<12)
        for descriptor in coll:
            if isinstance(descriptor, WindowsDTBDescriptor):
                pid = descriptor.owner().UniqueProcessId.v()
            elif isinstance(descriptor, VirtualAddressDescriptor):
                vaddr = descriptor.address

        return (pid, vaddr)


    def _get_pte_addr_and_val(self, pfndbentry, pfn):
        """Returns pte_phys address and pte_value for a given MMPFN struct.
        It furthermore checks for a PTE pointer diff and returns the result.
        
        Return value: (phys_pte_addr, pte_value, is_large_page, pte_ptr_diff)
        """
        containing_page = int(pfndbentry.u4.PteFrame)
        pte_offset = (int(pfndbentry.PteAddress) & 0xFFF)
        phys_pte_addr = (containing_page << self.PAGE_BITS) | pte_offset
        is_large_page = False
        pte_ptr_diff = False

        # Especially the first MMPFN instances tend to have a too large value
        # (0xff0000000000 would be 255 TB) in the PteFrame field.
        # Not sure about the reason yet. Potentially used for other purposes.
        if phys_pte_addr >= 0xff0000000000:
            return (None, None, is_large_page, pte_ptr_diff)

        # Kernel AS read_pte implementation uses the physical_address_space
        pte_value = self.session.kernel_address_space.read_pte(phys_pte_addr)
        if self._get_pfn_from_pte_value(pte_value) == pfn:
            # While the calculation for phys_pte_addr is different for large
            # pages (see _get_pte_addr_and_val_large), there are cases where
            # the "normal" calculation points to the correct PTE by accident.
            # So we check the PTE for actually being a large page:
            is_large_page =  \
                (pte_value & self.large_page_mask) == self.large_page_mask \
                and pte_value & self.valid_mask
            return (phys_pte_addr, pte_value, is_large_page, pte_ptr_diff)
        
        # MMPFN struct might belong to a large page
        tmp_phys_pte_addr, tmp_pte_value, is_large_page = \
            self._get_pte_addr_and_val_large(pfndbentry, pfn)
        if is_large_page:
            return (tmp_phys_pte_addr, tmp_pte_value, is_large_page, pte_ptr_diff)
        
        # It's not a large page, but still a PFN mismatch: SUSPICIOUS
        pte_ptr_diff = True
        return (phys_pte_addr, pte_value, is_large_page, pte_ptr_diff)


    # TODO add support for huge pages
    # CAUTION: The algorithm here is still experimental and must be evaluated
    # thoroughly.
    def _get_pte_addr_and_val_large(self, pfndbentry, pfn):
        """Returns pte_phys address and pte_value if the given MMPFN struct
        belongs to a large page, None otherwise."""
        # TODO The following PteAddress calculation has only been tested on
        # Windows 10 x64 1511. E.g. in Windows 7 this works differently
        # (see "What makes it page" p.394) and should be added/tested.
        pte_offset = ((pfndbentry.PteAddress >> self.PAGE_BITS) & 
                      (self.PAGE_BITS_MASK >> 3))
        pte_offset <<= 3
        phys_pte_addr = (pfndbentry.u4.PteFrame << self.PAGE_BITS) | pte_offset
        pte_value = self.session.kernel_address_space.read_pte(phys_pte_addr)
        # Large pages are non-pageable (see Windows Internals 7th Edition
        # Part 1, page 304), so the PTE should be valid.
        if not pte_value & self.valid_mask:
            return (None, None, False)

        # Each MMPFN struct for a given large page points to
        # the same PTE (PDE).
        first_pfn = self._get_pfn_from_pte_value(pte_value)
        last_pfn = first_pfn + (self.LARGE_PAGE_SIZE / 0x1000) - 1
        if (pte_value & self.large_page_mask) == self.large_page_mask and \
                first_pfn <= pfn <= last_pfn:
            return (phys_pte_addr, pte_value, True)

        return (None, None, False)


    # TODO raw read multiple MMPFN structs at once and do first checks
    # with bit masks to improve performance
    def get_pfndb_analysis_results(self):
        """Enumerates all PFN DB elements and checks for:
        - zero PTEs (PTE erasure)
        - duplicate PTE pointers (PTE remapping)
        - PTE pointer diffs between the MMPFN struct and
          the PTE itself (PTE remapping)
        
        Returns all hits, indexed by the PID and PFN.
        """
        # PFN entry types that are ignored for the duplicate check
        # 0: 'Zeroed', 1: 'Free', 2: 'Standby', 5: 'Bad'
        pfn_excluded_types = [0, 1, 2, 5]
        
        all_pte_pointers = dict()
        dup_pte_ptrs = dict()
        pfn_ana_result = dict()

        # This is a workaround to get MmHighestPhysicalPage, the highest
        # physical page: last valid PFN entry.
        # As this field does not seem to be set anymore in Windows 10's KDBG,
        # the following one liner simply gets the phys_end field of the last
        # run, which should be equal to MmHighestPhysicalPage, and increments
        # it by one.
        # For details see "What makes it page" p. 495-496
        # Note: We tested multiple Windows 7/10 VMs (x64) and at least did not
        # encounter a PTE with a PFN higher than MmHighestPhysicalPage.
        #
        # Potential alternative: Get NumberOfPhysicalPages from _KUSER_SHARED_DATA
        # Problem: As there are holes, NumberOfPhysicalPages will not result
        # in last PFN DB entry. So we are not using it here.
        hpp = [x for x in self.session.plugins.phys_map().collect()][-1][1]>>12
        hpp += 1
        pfn = 0
        while pfn < hpp:
            self.session.report_progress(
                "Enumerating all PFN DB entries: %d / %d", pfn, hpp)

            pfndbentry = self.mmpfn_db[pfn]
            if pfndbentry.u3.e1.PageLocation not in pfn_excluded_types and \
                    not pfndbentry.u4.PrototypePte:

                # First, we get the PTE (its value and phyical address),
                # while also checking for a large page.
                phys_pte_addr, pte_value, is_large_page, pte_ptr_diff = \
                    self._get_pte_addr_and_val(pfndbentry, pfn)
                self.pte_addrs[pfn] = phys_pte_addr

                if phys_pte_addr == None and pte_value == None:
                    pfn += 1
                    continue

                dup_pte_ptr = phys_pte_addr in all_pte_pointers
                
                # PTE erasure is currently only triggered with demand zero PTEs
                # (completely zero or only protection flag set).
                # It should, however, also consider some more bits, which could
                # be set by an attacker to circumvent this check.
                zero_pte = self.is_demand_zero_pte(pte_value) 

                if zero_pte or pte_ptr_diff or \
                        (dup_pte_ptr and not is_large_page):
                    # Retrieving the owning process.
                    pid, vaddr = self._get_pid_and_vaddr(pfn)
                    if not pid in pfn_ana_result:
                        pfn_ana_result[pid] = dict()

                    pfn_ana_result[pid][pfn] = \
                        { 'zero_pte': zero_pte,
                          'dup_pte_ptr': dup_pte_ptr,
                          'pte_ptr_diff': pte_ptr_diff,
                          'pte_value': pte_value,
                          'phys_pte_addr': phys_pte_addr,
                          'vaddr': vaddr }

                    if dup_pte_ptr:
                        el = dup_pte_ptrs.setdefault(phys_pte_addr, [])
                        el.append(pfn)
                    
                el = all_pte_pointers.setdefault(phys_pte_addr, [])
                el.append(pfn)

                if is_large_page:
                    # Large pages consist of physically contiguous small pages
                    # (see Windows Internals 7th Edition Part 1, page 304),
                    # so we can skip now the analysis of the next X page frames.
                    tmp_pfn = self._get_pfn_from_pte_value(pte_value)
                    if tmp_pfn != pfn:
                        pid, vaddr = self._get_pid_and_vaddr(pfn)
                        self.session.logging.warning(
                            "PFN diff for PFN 0x{:x} with 0x{:x} for a large "
                            "page, while iterating the PFN DB. Large page "
                            "support is still experimental and this issue "
                            "should be checked. This pfn belongs to process "
                            "{:d} and vaddr: 0x{:x}."
                            .format(pfn, tmp_pfn, pid, vaddr))
                        pfn += 1
                    else:
                        pfn += int(self.LARGE_PAGE_SIZE / 0x1000)
                else:
                    pfn += 1
            else:
                pfn += 1

        # Reiterating over all dup_pte pointers to also mark the first occurence
        for phys_pte_addr, dup_pfns in dup_pte_ptrs.items():
            all_pfns_for_ppa = all_pte_pointers[phys_pte_addr]
            diff = [x for x in all_pfns_for_ppa if x not in dup_pfns]
            for pfn in diff:
                pid, vaddr = self._get_pid_and_vaddr(pfn)
                pfndbentry = self.mmpfn_db[pfn]
                phys_pte_addr, pte_value, _, _ = \
                    self._get_pte_addr_and_val(pfndbentry, pfn)
                
                if not pid in pfn_ana_result:
                    pfn_ana_result[pid] = dict()

                if pfn in pfn_ana_result[pid]:
                    pfn_ana_result[pid][pfn]['dup_pte_ptr'] = True
                else:
                    pfn_ana_result[pid][pfn] = \
                        { 'zero_pte': False,
                          'dup_pte_ptr': True,
                          'pte_ptr_diff': False,
                          'pte_value': pte_value,
                          'phys_pte_addr': phys_pte_addr,
                          'vaddr': vaddr }
        return pfn_ana_result


    def collect(self):
        pfndb_analysis_result = dict()
        result_set = list()
        all_pte_pfns = dict()
        duplicate_pfns = set()

        if not self.plugin_args.test_only_orphaned_pages:
            if self.filtering_requested:
                self.session.logging.warning(
                    "This plugin should be run without any process filtering "
                    "as at least the duplicate PFN check does only work "
                    "reliably without process filtering.")
            pfndb_analysis_result = self.get_pfndb_analysis_results()

        # We are now iterating over all page tables for all processes, and
        # check for duplicate PFNs, MAS remapping and PTE pointer diffs
        for proc in self.filter_processes():
            pid = proc.pid.v()

            if not self.init_for_proc(proc): continue

            end_addr = self.session.GetParameter("highest_usermode_address")

            for run in self.get_all_pages_method(start=0, end=end_addr):
                self.session.report_progress(
                    "Inspecting Pid %d: 0x%08X", pid, run.start)
                
                # We ignore null/demand zero PTEs at this point, as we can't
                # extract any PFN from those for the next analysis steps.
                #
                # Detection of PTE Erasure is done at the end of this
                # function, together with get_pfndb_analysis_results.
                pte_value = run.data['pte_value']
                if self.is_demand_zero_pte(pte_value): continue

                pfn = None
                if run.file_offset:
                    pfn = run.file_offset >> self.PAGE_BITS

                vad = self.get_vad_for_address(run.start,
                                               supress_warning=True)
                is_orphaned_page = vad == None

                tmp_result = dict(proc=pid,
                                  vaddr=run.start,
                                  pfn=pfn,
                                  pte_value=pte_value,
                                  orphaned_page=is_orphaned_page,
                                  dup_pfn=False,
                                  dup_pte_ptr=False,
                                  pte_ptr_diff=False,
                                  zero_pte=False
                                 )

                if self.plugin_args.test_only_orphaned_pages:
                    tmp_result['dup_pte_ptr'] = "Not Tested"
                    tmp_result['pte_ptr_diff'] = "Not Tested"
                    tmp_result['dup_pfn'] = "Not Tested"
                    tmp_result['zero_pte'] = "Not Tested"

                elif pfn:
                    pfndbentry = self.mmpfn_db[pfn]

                    # We only check private pages because duplicate PFNs are
                    # pretty common for shared memory.
                    # Also, comparing the PTE address with the PFN entry
                    # pointer for shared memory doesn't make sense because a
                    # PFN entry can only point to one PTE, but multiple PTEs
                    # can point to the same PFN entry.
                    if not pfndbentry.u4.PrototypePte:
                        # This check compares the PTE address from the 
                        # process' paging structure enumeration with the
                        # PteAddress pointer from the PFN entry.
                        phys_pte_addr = None
                        try:
                            phys_pte_addr = self.pte_addrs[pfn]
                        except KeyError:
                            phys_pte_addr, _, _, _ = \
                                self._get_pte_addr_and_val(pfndbentry, pfn)

                        tmp_result['pte_ptr_diff'] = \
                            phys_pte_addr != run.data['pte_addr']

                        if pid in pfndb_analysis_result and \
                                pfn in pfndb_analysis_result[pid]:
                            el = pfndb_analysis_result[pid][pfn]
                            tmp_result['dup_pte_ptr'] = el['dup_pte_ptr']
                            tmp_result['zero_pte'] = el['zero_pte']
                            if not tmp_result['pte_ptr_diff'] == True:
                                tmp_result['pte_ptr_diff'] = el['pte_ptr_diff']
                            
                        # The last check tests if this PFN has already been
                        # seen in any PTE, which shouldn't be the case for
                        # private memory.
                        # Note: Windows' memory combining feature might lead
                        # to such a case for private memory, but we would
                        # expect a PrototypePte in this case, which is ignored
                        # in the beginning. This has, however, not yet been
                        # evaluated!

                        if pfn in all_pte_pfns:
                            duplicate_pfns.add(pfn)
                            tmp_result['dup_pfn'] = True

                    # We also add PFNs for shared memory for the dup_pfn
                    # test, as we want to identify private PTEs remapped
                    # to shared pages.
                    el = all_pte_pfns.setdefault(pfn, [])
                    el.append([pid, run.start, pte_value])

                if True in [tmp_result['orphaned_page'],
                            tmp_result['dup_pfn'],
                            tmp_result['dup_pte_ptr'],
                            tmp_result['pte_ptr_diff'],
                            tmp_result['zero_pte']]:
                    result_set.append(tmp_result)

        # Setting dup_pfn on all results if applicable, otherwise create
        # result for the first duplicate pfn (which at that time was the
        # occurence and yet no duplicate).
        for pfn in duplicate_pfns:
            results_for_pfn = [x for x in result_set if x['pfn'] == pfn]
            # all_pte_pfns contains all processes that resolve to the given pfn
            # We now search for any process with a given vaddr, that is not
            # already part of the resultset
            for data in all_pte_pfns[pfn]:
                match_found = False
                for result in results_for_pfn:
                    if data[0] == result['proc'] and data[1] == result['vaddr']:
                        match_found = True
                        result['dup_pfn'] = True
                        break

                if match_found: continue

                result_set.append(
                    dict(proc=data[0],
                         vaddr=data[1],
                         pfn=pfn,
                         pte_value=data[2],
                         orphaned_page=False,
                         dup_pfn=True,
                         dup_pte_ptr=False,
                         pte_ptr_diff=False,
                         zero_pte=False
                        )
                )

        # Now merging the pfndb_analysis_results with the PTE analysis results 
        for pid, pid_data in pfndb_analysis_result.items():
            # if pid == 4: continue
            
            for pfn, pfn_data in pid_data.items():
                match_found = False
                for result in result_set:
                    if result['pfn'] == pfn:
                        match_found = True
                        result['dup_pte_ptr'] = pfn_data['dup_pte_ptr']
                        result['zero_pte'] = pfn_data['zero_pte']
                        if not result['pte_ptr_diff'] == True:
                            result['pte_ptr_diff'] = pfn_data['pte_ptr_diff']
                
                if not match_found:
                    # As this data comes from the PFN DB enumeration, those
                    # tests have potentially not been performed if the PFN is
                    # not referenced by any process' PTE
                    orphaned_page = "Not tested"
                    dup_pfn = "Not tested"
                    
                    if pfn_data['zero_pte']:
                        orphaned_page = "Not applicable"
                        dup_pfn = "Not applicable"

                    result_set.append(
                        dict(proc=pid,
                             vaddr=pfn_data['vaddr'],
                             pfn=pfn,
                             pte_value=pfn_data['pte_value'],
                             orphaned_page=orphaned_page,
                             dup_pfn=dup_pfn,
                             dup_pte_ptr=pfn_data['dup_pte_ptr'],
                             pte_ptr_diff=pfn_data['pte_ptr_diff'],
                             zero_pte=pfn_data['zero_pte']
                            )
                    )            

        for result in sorted(result_set,
                             key= lambda x: (x['proc'], x['vaddr'])):
            if self.dump_dir:
                renderer = self.session.GetRenderer()
                filename = "pid.{:d}_vaddr.0x{:08x}_pfn.0x{:08x}.dmp".format(
                pid, result['vaddr'], result['pfn'])
    
                with renderer.open(directory=self.dump_dir,
                                   filename=filename,
                                   mode='wb') as fd:
                    phys_offset = result['pfn'] << self.PAGE_BITS
                    fd.write(self.session.physical_address_space.read(
                        phys_offset, self.PAGE_SIZE))
                    renderer.format(
                        "Dumped content to {0}/{1}\n", self.dump_dir, filename)
            yield result
