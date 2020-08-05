#  Plugin to detect PTE subversions resp. MAS remapping on Windows.
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

# Some parts are taken from Rekall:
#
# Rekall Memory Forensics
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# Mike Auty
# Michael Cohen
# Jordi Sanchez
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

"""This plugin detects PTE subversions resp. MAS remapping on Windows.
References:
https://dfrws.org/presentation/hiding-process-memory-via-anti-forensic-techniques/
https://www.blackhat.com/us-20/briefings/schedule/index.html#hiding-process-memory-via-anti-forensic-techniques-20661
"""

import struct
import logging
from past.utils import old_div
from builtins import object

from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.framework.objects import utility
from volatility.plugins.windows import pslist, handles, vadinfo
from volatility.framework import interfaces, constants, exceptions, renderers, contexts, objects

vollog = logging.getLogger(__name__)

class PteRun(object):
    
    def __init__(self, vaddr=None, length=None, layer=None, phys_offset=None,
                 pte_value=None, pte_addr=None, is_proto=None):
        self.vaddr = vaddr
        self.length = length
        self.layer = layer
        self.phys_offset = phys_offset
        self.pte_value = pte_value
        self.pte_addr = pte_addr
        self.is_proto = is_proto


    def read(self):
        return self.layer.read(self.phys_offset, self.length)


class PteSubMasRemapDet(interfaces.plugins.PluginInterface):
    """This plugin implements the detection of PTE subversions and 
    MAS remapping on Windows."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dtb = None
        self.proc_layer = None
        self.phys_layer = None
        self.valid_mask = 1
        self.arch = None
        self.ntkrnlmp = None
        self.mmpte_size = None
        self.PAGE_BITS = None
        self.resolved_dtbs = dict()
        self.proc = None
        self.vadlist = list()
        self.pte_addrs = dict()


    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Memory layer for the kernel',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolTableRequirement(name = "nt_symbols",
                                                    description = "Windows kernel symbols"),
                requirements.BooleanRequirement(name = "dump_memory",
                                                description = "Dumps the hidden memory to files.",
                                                default = False,
                                                optional = True),
                requirements.PluginRequirement(name = 'pslist',
                                               plugin = pslist.PsList,
                                               version = (1, 0, 0)),
                requirements.IntRequirement(name = 'pid',
                                            description = "Process ID to include (all other processes are excluded)",
                                            optional = True),
                requirements.BooleanRequirement(name = 'test_only_orphaned_pages',
                                            description = 'Only test pages for not belonging to any VAD (detects MAS remapping).',
                                            default = False,
                                            optional = True)]


    def run(self):

        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])

        return renderers.TreeGrid([("PID", int),
                                   ("vaddr", format_hints.Hex),
                                   ("PFN", format_hints.Hex),
                                   ("pte_value", format_hints.Hex),
                                   ("orphaned_page", str),
                                   ("dup_pfn", str),
                                   ("dup_pte_ptr", str),
                                   ("pte_ptr_diff", str),
                                   ("zero_pte", str)],
                                  self._generator(pslist.PsList.list_processes(self.context,
                                                                               self.config['primary'],
                                                                               self.config['nt_symbols'],
                                                                               filter_func = filter_func)))


    # static implementation of get_protection from class MMVAD_SHORT
    @classmethod
    def get_protection(cls, protect, protect_values, winnt_protections):
        """Get the VAD's protection constants as a string."""

        try:
            value = protect_values[protect]
        except IndexError:
            value = 0

        names = []

        for name, mask in winnt_protections.items():
            if value & mask != 0:
                names.append(name)

        return "|".join(names)


    def read_pte_value(self, layer, addr):
        pte = 0

        try:
            pte_raw = layer.read(addr, 8)
            pte = struct.unpack('<Q', pte_raw)[0]
        except exceptions.InvalidAddressException:
            pass

        return pte


    def get_subsec_protection(self, protect):
        if not self._protect_values:
             self._protect_values = vadinfo.VadInfo.protect_values(context = self.context,
                                                                   layer_name = self.config["primary"],
                                                                   symbol_table = self.config["nt_symbols"])
        return self.get_protection(protect, self._protect_values, vadinfo.winnt_protections)


    def get_phys_addr_for_proto_pte(self, proto_pte_offset):
        pte = self.context.object(self.config["nt_symbols"] + constants.BANG + "_MMPTE",
                                  offset = proto_pte_offset,
                                  layer_name = self.config["primary"])

        if pte.u.Hard.Valid == 1:
            return pte.u.Hard.PageFrameNumber << self.PAGE_BITS

        if pte.u.Soft.Prototype == 0 and pte.u.Trans.Transition == 1:
            return pte.u.Trans.PageFrameNumber << self.PAGE_BITS
        
        return None


    @classmethod
    def ca_contains_image_file(cls, control_area):

        if control_area.FilePointer.Value:
            file_obj = control_area.FilePointer.dereference().cast("_FILE_OBJECT")

            if file_obj.SectionObjectPointer:
                sec_obj_poi = file_obj.SectionObjectPointer.dereference().cast("_SECTION_OBJECT_POINTERS")

                if sec_obj_poi.ImageSectionObject:
                    return True
    
        return False


    # taken from rekall-core/rekall/plugins/addrspaces/amd64.py
    def _get_pde_addr(self, pdpte_value, vaddr):
        if pdpte_value & self.valid_mask:
            return ((pdpte_value & 0xffffffffff000) |
                    ((vaddr & 0x3fe00000) >> 18))


    # based on rekall-core/rekall/plugins/addrspaces/amd64.py
    def _get_available_PDPTEs(self, start=0, end=2**64):
        # Pages that hold PDEs and PTEs are 0x1000 bytes each.
        # Each PDE and PTE is eight bytes. Thus there are 0x1000 / 8 = 0x200
        # PDEs and PTEs we must test.
        for pml4e_index in range(0, 0x200):
            vaddr = pml4e_index << 39
            if vaddr > end:
                return

            next_vaddr = (pml4e_index + 1) << 39
            if start >= next_vaddr:
                continue

            pml4e_addr = ((self.dtb & 0xffffffffff000) |
                          ((vaddr & 0xff8000000000) >> 36))
            pml4e_value = self.read_pte_value(self.phys_layer, pml4e_addr)

            # TODO paged out paging structures have valid bit unset,
            # but if the pagefile is supplied, we still could read it.
            if not pml4e_value & self.valid_mask:
                continue

            tmp1 = vaddr
            for pdpte_index in range(0, 0x200):
                vaddr = tmp1 + (pdpte_index << 30)
                if vaddr > end:
                    return

                next_vaddr = tmp1 + ((pdpte_index + 1) << 30)
                if start >= next_vaddr:
                    continue

                # Bits 51:12 are from the PML4E
                # Bits 11:3 are bits 38:30 of the linear address
                pdpte_addr = ((pml4e_value & 0xffffffffff000) |
                              ((vaddr & 0x7FC0000000) >> 27))
                pdpte_value = self.read_pte_value(self.phys_layer, pdpte_addr)

                # TODO paged out paging structures have valid bit unset,
                # but if the pagefile is supplied, we still could read it.
                if not pdpte_value & self.valid_mask:
                    continue

                yield [vaddr, pdpte_value, pdpte_addr]


    # based on rekall-core/rekall/plugins/addrspaces/amd64.py
    def _get_available_PDEs(self, vaddr, pdpte_value, start=0, end=2**64):
        # This reads the entire PDE table at once - On
        # windows where IO is extremely expensive, its
        # about 10 times more efficient than reading it
        # one value at the time - and this loop is HOT!

        pde_table_addr = self._get_pde_addr(pdpte_value, vaddr)
        if pde_table_addr is None:
            return

        data = self.phys_layer.read(pde_table_addr, 8 * 0x200)
        pde_table = struct.unpack("<" + "Q" * 0x200, data)

        tmp2 = vaddr
        for pde_index in range(0, 0x200):
            vaddr = tmp2 + (pde_index << 21)
            if vaddr > end:
                return

            next_vaddr = tmp2 + ((pde_index + 1) << 21)
            if start >= next_vaddr:
                continue

            pde_value = pde_table[pde_index]

            # TODO Paged out paging structures have valid bit unset,
            # but if the pagefile is supplied, we still could read it.
            # Currently, we skip PDE if it is not valid or not in transition.
            if not (pde_value & self.valid_mask or 
                    pde_value & self.proto_transition_mask ==
                    self.transition_mask):
                continue

            yield [vaddr, pde_table[pde_index], pde_table_addr + pde_index * 8]


    # taken from rekall-core/rekall/plugins/windows/pagefile.py
    def _get_available_PTEs(self, pde_value, vaddr, start=0, end=2**64,
                            ignore_vad=False):
        """Scan the PTE table and yield address ranges which are valid."""
        
        # This reads the entire PTE table at once - On
        # windows where IO is extremely expensive, its
        # about 10 times more efficient than reading it
        # one value at the time - and this loop is HOT!
        pte_table_addr = (pde_value & 0xffffffffff000) | \
                         ((vaddr & 0x1ff000) >> 9)

        # Invalid PTEs.
        if pte_table_addr is None:
            return

        data = self.phys_layer.read(pte_table_addr, 8 * 0x200)
        pte_table = struct.unpack("<" + "Q" * 0x200, data)

        tmp = vaddr
        for i in range(0, len(pte_table)):
            pfn = i << 12
            pte_value = pte_table[i]

            vaddr = tmp | pfn
            if vaddr > end:
                return

            next_vaddr = tmp | ((i + 1) << 12)
            if start >= next_vaddr:
                continue

            yield [vaddr, pte_value, pte_table_addr+i*8]


    def get_all_pages(self, start=0, end=2**64):
        """Simply enumerates all Paging structures and returns the virtual 
        address and, if possible, the PFN.

        Yields Run objects for all available ranges in the virtual address
        space.
        """

        for pdpte_vaddr, pdpte_value, pdpte_addr in self._get_available_PDPTEs(start, end):
            if pdpte_vaddr & self.valid_mask and \
                    pdpte_value & self.page_size_mask:
                        # huge page (1 GB)
                phys_offset = ((pdpte_value & 0xfffffc0000000) |
                               (pdpte_vaddr & 0x3fffffff))
                
                yield PteRun(vaddr=pdpte_vaddr,
                             length=self.HUGE_PAGE_SIZE,
                             phys_offset=phys_offset,
                             layer=self.phys_layer,
                             pte_value=pdpte_value,
                             is_proto=False,
                             pte_addr=pdpte_addr)
                continue
            
            for pde_vaddr, pde_value, pde_addr in self._get_available_PDEs(pdpte_vaddr, pdpte_value, start, end):
                if pde_value & self.valid_mask and \
                        pde_value & self.page_size_mask:
                    # large page
                    phys_offset = ((pde_value & 0xfffffffe00000) |
                                   (pde_vaddr & 0x1fffff))
                    yield PteRun(vaddr=pde_vaddr,
                                 length=self.LARGE_PAGE_SIZE,
                                 phys_offset=phys_offset,
                                 layer=self.phys_layer,
                                 pte_value=pde_value,
                                 is_proto=False,
                                 pte_addr=pde_addr)
                    continue

                for vaddr, pte_value, pte_addr in self._get_available_PTEs(pde_value, pde_vaddr, start, end):
                    phys_offset = \
                        self._get_phys_addr_from_pte(vaddr, pte_value)

                    yield PteRun(vaddr=vaddr,
                                 length=self.PAGE_SIZE,
                                 phys_offset=phys_offset,
                                 layer=self.phys_layer,
                                 pte_value=pte_value,
                                 is_proto=False,
                                 pte_addr=pte_addr)


    def _get_pfn_from_pte_value(self, pte_value):
        if pte_value & self.valid_mask:
            return ((pte_value & self.hard_pfn_mask) >> self.hard_pfn_start)

        elif not (pte_value & self.prototype_mask) and pte_value & self.transition_mask:
            return ((pte_value & self.trans_pfn_mask) >> self.trans_pfn_start)

        return None


    def _get_phys_addr_from_pte(self, vaddr, pte_value):
        pfn = self._get_pfn_from_pte_value(pte_value)
        if not pfn:
            return None
        return (pfn << self.PAGE_BITS) | (vaddr & 0xFFF)


    def is_demand_zero_pte(self, pte_value):
        
        # We are not interested in DemandZero pages
        if pte_value == 0:
            return True

        # We are also not interested in Guard Pages or 
        # Demand Zero pages with a modified Protection.
        # These pages have only the _MMPTE_SOFTWARE.Protection
        # field set.
        if not (pte_value & self.soft_protection_mask_negated):
            return True
            
        return False


    def get_highest_phys_page(self):
        """This is a workaround to get MmHighestPhysicalPage, the highest
        physical page: last valid PFN entry.
        As this field does not seem to be set anymore in Windows 10's KDBG,
        the following function simply gets the phys_end field of the last
        _PHYSICAL_MEMORY_DESCRIPTOR Run, which should be equal to
        MmHighestPhysicalPage, and increments it by one.
        For details see "What makes it page" p. 495-496
        Note: We tested multiple Windows 7/10 VMs (x64) and at least did not
        encounter a PTE with a PFN higher than MmHighestPhysicalPage.
        
        Potential alternative: Get NumberOfPhysicalPages from _KUSER_SHARED_DATA
        Problem: As there are holes, NumberOfPhysicalPages will not result
        in last PFN DB entry. So we are not using it here.
        """
        phys_mem_desc = self.context.symbol_space.get_symbol(self.config["nt_symbols"] + constants.BANG + "MmPhysicalMemoryBlock").address
        phys_mem_desc = self.ntkrnlmp.object(object_type = 'pointer', offset = phys_mem_desc)
        phys_mem_desc = phys_mem_desc.dereference()
        phys_mem_desc = phys_mem_desc.cast(self.config["nt_symbols"] + constants.BANG + "_PHYSICAL_MEMORY_DESCRIPTOR")

        phys_mem_run_string = self.config["nt_symbols"] + constants.BANG + "_PHYSICAL_MEMORY_RUN"
        phys_mem_run_type = self.context.symbol_space.get_type(phys_mem_run_string)
        phys_mem_runs = phys_mem_desc.Run.cast("array", count = phys_mem_desc.NumberOfRuns, subtype = phys_mem_run_type)

        last_run = phys_mem_runs[-1]
        return last_run.BasePage + last_run.PageCount + 1


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
        pte_value = self.read_pte_value(self.phys_layer, phys_pte_addr)
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
        pte_value = self.read_pte_value(self.phys_layer, phys_pte_addr)
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


    # taken from rekall-core/plugins/windows/pfn.py
    def ptov(self, physical_address):
        
        # TODO get dynamically
        table_names = ["Phys", "PTE", "PDE", "PDPTE", "PML4E", "DTB"]
        bit_divisions = [12, 9, 9, 9, 9, 4]
        
        # A list of PTEs and their physical addresses.
        physical_addresses = dict(Phys=physical_address)

        # The physical and virtual address of the pte that controls the named
        # member.
        phys_addresses_of_pte = {}
        ptes = {}
        p_addr = physical_address
        pfns = {}

        # Starting with the physical address climb the PFN database in reverse
        # to reach the DTB. At each page table entry we store the its physical
        # offset. Then below we traverse the page tables in the forward order
        # and add the bits into the virtual address.
        for i, name in enumerate(table_names):
            pfn = p_addr >> self.PAGE_BITS
            pfns[name] = pfn_obj = self.mmpfn_db[pfn]

            # The PTE which controls this pfn.
            pte = pfn_obj.PteAddress

            if i > 0:
                physical_addresses[name] = ptes[
                    table_names[i-1]].vol.offset

            # The physical address of the PTE.
            p_addr = ((pfn_obj.u4.PteFrame << self.PAGE_BITS) |
                      (pte & 0xFFF))

            phys_addresses_of_pte[name] = p_addr

            # Hold on to the PTE in the physical AS. This is important as it
            # ensures we can always access the correct PTE no matter the process
            # context.
            ptes[name] = self.context.object(
                self.config["nt_symbols"] + constants.BANG + "_MMPTE",
                offset = p_addr,
                layer_name = "memory_layer")

        # The DTB must be page aligned.
        dtb = p_addr & ~0xFFF

        # Now we construct the virtual address by locating the offset in each
        # page table where the PTE is and deducing the bits covered within that
        # range.
        virtual_address = 0
        start_of_page_table = dtb

        for name, bit_division in reversed(list(zip(
                table_names, bit_divisions))):
            pte = ptes[name]
            virtual_address += old_div((
                ptes[name].vol.offset - start_of_page_table), self.mmpte_size)

            virtual_address <<= bit_division

            # The physical address where the page table begins. The next
            # iteration will find the offset of the next higher up page table
            # level in this table.
            start_of_page_table = pte.u.Hard.PageFrameNumber << self.PAGE_BITS

        virtual_address = virtual_address & self.kernel_layer.maximum_address
        virtual_address += physical_address & 0xFFF
        
        dtb_pfn = dtb >> 12
        if dtb_pfn in self.resolved_dtbs:
            return (self.resolved_dtbs[dtb_pfn], virtual_address)
        
        pfn_obj = self.mmpfn_db[dtb_pfn]
        eproc = pfn_obj.u1.Flink.cast(
            self.config["nt_symbols"] + constants.BANG + "pointer",
            subtype=self.ntkrnlmp.get_type("_EPROCESS")
            ).dereference()

        pid = int(eproc.UniqueProcessId)
        self.resolved_dtbs[dtb_pfn] = pid
        return (pid, virtual_address)


    def _init_masks(self):
        # TODO those should be generated dynamically
        # Ideally extend the Bitfield class
        self.prototype_mask = 0b10000000000
        self.transition_mask = 0b100000000000
        self.proto_protoaddress_mask = 0xffffffffffff0000
        self.proto_protoaddress_start = 16
        self.soft_pagefilehigh_mask = 0xffffffff00000000
        self.soft_pagefilehigh_start = 32
        self.soft_pagefilelow_mask = 0b11110
        self.soft_pagefilelow_start = 1
        self.soft_protection_start = 5
        self.soft_protection_mask = (0b11111 << self.soft_protection_start)
        self.soft_protection_mask_negated = \
            0xffffffffffffffff ^ self.soft_protection_mask
        self.proto_protection_start = 11
        self.proto_protection_mask = (0b11111 << self.proto_protection_start)
        self.proto_transition_mask = self.prototype_mask | self.transition_mask
        self.nx_mask = 1 << 63
        self.hard_pfn_mask = 0xfffffffff000
        self.hard_pfn_start = 12
        self.trans_pfn_mask = 0xfffffffff000
        self.trans_pfn_start = 12
        self.page_size_mask = 0b10000000
        self.large_page_mask = 0b10000000


    def _init_variables(self):
        self.phys_layer = self.context.layers['memory_layer']
        self.kernel_layer = self.context.layers['primary']
        
        arch = self.kernel_layer.metadata.get("architecture")
        if arch == "Intel64":
            self.get_all_pages_method = self.get_all_pages
            self.proto_pointer_identifier = 0xffffffff0000

        elif arch == "Intel32":
            # TODO add support for x86
            # ~ self.get_all_pages_method = self.get_all_pages_x86
            self.proto_pointer_identifier = 0xffffffff
            vollog.error("Unsupported architecture: {:s}".format(arch))
            raise RuntimeError("Unsupported architecture")

        else:
            vollog.error("Unsupported architecture: {:s}".format(arch))
            raise RuntimeError("Unsupported architecture")

        self.PAGE_BITS = self.kernel_layer._page_size_in_bits
        self.PAGE_SIZE = 1 << self.PAGE_BITS
        self.PAGE_BITS_MASK = self.PAGE_SIZE - 1
        # The empty page test uses this a lot, so we keep it once
        self.ALL_ZERO_PAGE = b"\x00" * self.PAGE_SIZE
        # The following pages will probably not occur that much,
        # and we don't want to keep a gigabyte of zeroes in memory
        
        # TODO make dynamic
        self.LARGE_PAGE_SIZE = 0x200000
        self.LARGE_PAGE_BITS = self.LARGE_PAGE_SIZE.bit_length() - 1
        self.LARGE_ARM_PAGE_SIZE = self.LARGE_PAGE_SIZE * 2
        self.LARGE_ARM_PAGE_BITS = self.LARGE_ARM_PAGE_SIZE.bit_length() - 1
        self.HUGE_PAGE_SIZE = 0x40000000
        self.HUGE_PAGE_BITS = self.HUGE_PAGE_SIZE.bit_length() - 1
        
        layer_name = self.config['primary']
        # TODO use hardcoded value in case MmHighestUserAddress is not present
        # also: could be gathered from EPROCESS struct: HighestUserAddress
        # see rekall-core/plugins/windows/kernel.py
        highest_user_addr = self.context.symbol_space.get_symbol(self.config["nt_symbols"] + constants.BANG + "MmHighestUserAddress").address
        kvo = self.context.layers[layer_name].config['kernel_virtual_offset']
        self.ntkrnlmp = self.context.module(self.config["nt_symbols"], layer_name = layer_name, offset = kvo)
        self.highest_user_addr = int(self.ntkrnlmp.object(object_type = 'pointer', offset = highest_user_addr))

        mmpte_type = self.ntkrnlmp.get_type("_MMPTE")
        self.mmpte_size = mmpte_type.vol.size
        
        # getting PFN DB
        self.hpp = self.get_highest_phys_page()
        self.mmpfn_db = self.ntkrnlmp.get_symbol("MmPfnDatabase").address
        self.mmpfn_db = self.ntkrnlmp.object(
            object_type = 'pointer',
            offset = self.mmpfn_db,
            subtype = self.ntkrnlmp.get_type("pointer"))
        self.mmpfn_db = self.mmpfn_db.dereference()
        self.mmpfn_db = self.mmpfn_db.cast(
            "array", count = self.hpp,
            subtype = self.ntkrnlmp.get_type("_MMPFN"))


    def get_vad_for_address(self, addr, supress_warning=False):
        for start, end, vad in self.vadlist:
            if start <= addr <= end:
                return vad
        if not supress_warning:
            vollog.warning("No VAD found for process {:d} and address 0x{:x}"
                           .format(self.proc.pid, addr))
        return None


    def get_proc_layer(self, proc):
        layer_name = self.config['primary'] + "_Process" + str(proc.UniqueProcessId)
        if layer_name not in self.context.layers:
            layer_name = proc.add_process_layer()
            
        return self.context.layers[layer_name]


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

        pfn = 0
        while pfn < self.hpp:
            self._progress_callback((pfn/self.hpp) * 100, "Enumerating PFN DB")

            pfndbentry = self.mmpfn_db[pfn]
            if pfndbentry.u3.e1.PageLocation not in pfn_excluded_types and \
                    not pfndbentry.u4.PrototypePte:

                # First, we get the PTE (its value and phyical address),
                # while also checking for a large page.
                pte_phys_addr, pte_value, is_large_page, pte_ptr_diff = \
                    self._get_pte_addr_and_val(pfndbentry, pfn)
                self.pte_addrs[pfn] = pte_phys_addr

                if pte_phys_addr == None and pte_value == None:
                    pfn += 1
                    continue

                dup_pte_ptr = pte_phys_addr in all_pte_pointers
                
                # PTE erasure is currently only triggered with demand zero PTEs
                # (completely zero or only protection flag set).
                # It should, however, also consider some more bits, which could
                # be set by an attacker to circumvent this check.
                zero_pte = self.is_demand_zero_pte(pte_value) 
                
                if zero_pte or pte_ptr_diff or \
                        (dup_pte_ptr and not is_large_page):
                    # Retrieving the owning process.
                    pid, vaddr = self.ptov(pfn << self.PAGE_BITS)
                    
                    if not pid in pfn_ana_result:
                        pfn_ana_result[pid] = dict()

                    pfn_ana_result[pid][pfn] = \
                        { 'zero_pte': zero_pte,
                          'dup_pte_ptr': dup_pte_ptr,
                          'pte_ptr_diff': pte_ptr_diff,
                          'pte_value': pte_value,
                          'pte_phys_addr': pte_phys_addr,
                          'vaddr': vaddr }

                    if dup_pte_ptr:
                        el = dup_pte_ptrs.setdefault(pte_phys_addr, [])
                        el.append(pfn)
                    
                el = all_pte_pointers.setdefault(pte_phys_addr, [])
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
        for pte_phys_addr, dup_pfns in dup_pte_ptrs.items():
            all_pfns_for_ppa = all_pte_pointers[pte_phys_addr]
            diff = [x for x in all_pfns_for_ppa if x not in dup_pfns]
            for pfn in diff:
                pid, vaddr = self.ptov(pfn << self.PAGE_BITS)
                pfndbentry = self.mmpfn_db[pfn]
                pte_phys_addr, pte_value, _, _ = \
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
                          'pte_phys_addr': pte_phys_addr,
                          'vaddr': vaddr }
        return pfn_ana_result


    def init_for_proc(self, proc):
        self.proc = proc
        self.dtb = int(proc.Pcb.DirectoryTableBase)
        self.proc_layer = self.get_proc_layer(proc)
        self.vadlist = list()
        for vad in proc.get_vad_root().traverse():
             self.vadlist.append((vad.get_start(), vad.get_end(), vad))


    def _generator(self, procs):
        self._init_masks()
        self._init_variables()

        pfndb_analysis_result = dict()
        result_set = list()
        all_pte_pfns = dict()
        duplicate_pfns = set()

        if not self.config.get('test_only_orphaned_pages', None):
            if self.config.get('pid', None):
                vollog.warning(
                    "This plugin should be run without any process filtering "
                    "as at least the duplicate PFN check does only work "
                    "reliably without process filtering.")
            pfndb_analysis_result = self.get_pfndb_analysis_results()

        # We are now iterating over all page tables for all processes, and
        # check for duplicate PFNs, MAS remapping and PTE pointer diffs
        for proc in procs:
            self.init_for_proc(proc)
            pid = int(proc.UniqueProcessId)

            # Since the support for large pages has been added, FPs for
            # System process seem to be gone, so we include the system process
            # for now.
            # ~ if self.kernel_layer.config.get('page_map_offset') == \
                    # ~ self.proc_layer.config.get('page_map_offset'):
                # ~ continue

            end_addr = self.highest_user_addr

            for pte_run in self.get_all_pages(start=0, end=end_addr):
                self._progress_callback(
                    0, "Enumerating page tables for Process {:d}: 0x{:08x}"
                       .format(pid, pte_run.vaddr))

                # We ignore null/demand zero PTEs at this point, as we can't
                # extract any PFN from those for the next analysis steps.
                #
                # Detection of PTE Erasure is done at the end of this
                # function, together with get_pfndb_analysis_results.
                pte_value = pte_run.pte_value
                if self.is_demand_zero_pte(pte_value): continue

                pfn = None
                if pte_run.phys_offset:
                    pfn = pte_run.phys_offset >> self.PAGE_BITS

                vad = self.get_vad_for_address(pte_run.vaddr,
                                               supress_warning=True)
                is_orphaned_page = vad == None

                tmp_result = dict(proc=pid,
                                  vaddr=pte_run.vaddr,
                                  pfn=pfn,
                                  pte_value=pte_value,
                                  orphaned_page=is_orphaned_page,
                                  dup_pfn=False,
                                  dup_pte_ptr=False,
                                  pte_ptr_diff=False,
                                  zero_pte=False
                                 )

                if self.config.get('test_only_orphaned_pages', None):
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
                            phys_pte_addr != pte_run.pte_addr

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
                    el.append([pid, pte_run.vaddr, pte_value])

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
            if self.config.get('dump_memory', True):
                filename = "pid.{:d}_vaddr.0x{:08x}_pfn.0x{:08x}.dmp".format(
                    pid, result['vaddr'], result['pfn'])
                filedumper = interfaces.plugins.FileInterface(filename)

                phys_addr = result['pfn'] << self.PAGE_BITS
                filedumper.data.write(self.phys_layer.read(phys_addr,
                                                           self.PAGE_SIZE))
                self.produce_file(filedumper)

            yield (0, (result['proc'], format_hints.Hex(result['vaddr']),
                       format_hints.Hex(result['pfn']),
                       format_hints.Hex(result['pte_value']),
                       str(result['orphaned_page']),
                       str(result['dup_pfn']),
                       str(result['dup_pte_ptr']),
                       str(result['pte_ptr_diff']),
                       str(result['zero_pte'])))
