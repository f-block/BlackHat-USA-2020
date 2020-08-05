#  Plugin to detect hidden shared memory on Windows.
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

"""This plugin detects hidden executable shared memory on Windows.
References:
https://dfrws.org/presentation/hiding-process-memory-via-anti-forensic-techniques/
https://www.blackhat.com/us-20/briefings/schedule/index.html#hiding-process-memory-via-anti-forensic-techniques-20661
"""

from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.plugins.windows import pslist, handles, vadinfo
from volatility.framework import interfaces, constants, exceptions, renderers, contexts
import logging
from volatility.framework import constants, interfaces, objects

vollog = logging.getLogger(__name__)

class HiddenSharedMemory(interfaces.plugins.PluginInterface):
    """Implements the detection of hidden executable shared memory
    on Windows."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._protect_values = None
        self._mmpte_size = None

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
                                            optional = True)]


    def run(self):

        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])

        return renderers.TreeGrid([("PID", int),
                                   ("Process", str),
                                   ("section_object", format_hints.Hex),
                                   ("ControlArea", format_hints.Hex),
                                   ("handle_name", str),
                                   ("number_of_pages", int)],
                                  self._generator(pslist.PsList.list_processes(self.context,
                                                                               self.config['primary'],
                                                                               self.config['nt_symbols'],
                                                                               filter_func = filter_func)))

    def cast_to_subsec(self, subsec_offset):
        return self.context.object(self.config["nt_symbols"] + constants.BANG + "_SUBSECTION",
                                   offset = subsec_offset,
                                   layer_name = self.config["primary"])


    def get_first_subsec(self, ca):
        # first subsection typically begins directly after the _CONTROL_AREA
        first_subsec_offset = ca.vol.offset + ca.vol.size
        return self.cast_to_subsec(first_subsec_offset)


    @classmethod
    def enumerate_subsections(cls, subsec):
        """Returns all SUBSECTION offsets for a given first subsection."""
        subsec_set = set()
        while subsec != 0 and subsec not in subsec_set:
            subsec_set.add(subsec.vol.offset)
            subsec = subsec.NextSubsection

        return subsec_set


    @classmethod
    def get_vad_subsection_set(cls, task):
        """Returns all SUBSECTIONs for all VADs for a given process."""

        subsec_set = set()
    
        for vad in task.get_vad_root().traverse():
            if vad.has_member('Subsection'):
                subsec = vad.Subsection.dereference().cast("_SUBSECTION")
                subsec_set = subsec_set.union(cls.enumerate_subsections(subsec))

        return subsec_set


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


    def get_subsec_protection(self, protect):
        if not self._protect_values:
             self._protect_values = vadinfo.VadInfo.protect_values(context = self.context,
                                                                   layer_name = self.config["primary"],
                                                                   symbol_table = self.config["nt_symbols"])
        return self.get_protection(protect, self._protect_values, vadinfo.winnt_protections)


    def filter(self, control_area):
        """Returns True if the control_area should be ignored."""
        if self.ca_contains_image_file(control_area):
            return True

        subsecs = [self.cast_to_subsec(x) for x in self.enumerate_subsections(self.get_first_subsec(control_area))]
        for subsec in subsecs:
            if 'EXECUTE' in self.get_subsec_protection(subsec.u.SubsectionFlags.Protection):
                return False

        return True


    # Simple implementation; should be replaced by one similar to 
    # extract_ca_file from Vol2. It will potentially be part of 
    # Vol3 in the future.
    def get_phys_addrs_from_subsec(self, subsec):
        phys_addrs = list()
        index = 0
        pte_count = subsec.PtesInSubsection
        if not self._mmpte_size:
            self._mmpte_size = subsec.SubsectionBase.dereference().vol.size

        base_offset = subsec.SubsectionBase.dereference().vol.offset
        for i in range(pte_count):
            phys_addr = self.get_phys_addr_for_proto_pte(base_offset + i * self._mmpte_size)
            if phys_addr:
                phys_addrs.append(phys_addr)

        return phys_addrs


    def get_phys_addr_for_proto_pte(self, proto_pte_offset):
        pte = self.context.object(self.config["nt_symbols"] + constants.BANG + "_MMPTE",
                                  offset = proto_pte_offset,
                                  layer_name = self.config["primary"])

        if pte.u.Hard.Valid == 1:
            return pte.u.Hard.PageFrameNumber << 12

        if pte.u.Soft.Prototype == 0 and pte.u.Trans.Transition == 1:
            return pte.u.Trans.PageFrameNumber << 12
        
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


    def _generator(self, procs):
    
        type_map = handles.Handles.get_type_map(context = self.context,
                                                layer_name = self.config["primary"],
                                                symbol_table = self.config["nt_symbols"])

        cookie = handles.Handles.find_cookie(context = self.context,
                                             layer_name = self.config["primary"],
                                             symbol_table = self.config["nt_symbols"])

        phys_layer = self.context.layers['memory_layer']

        # only used so that progress_callback doesn't overwrite results
        results = list()

        for proc in procs:
            try:
                object_table = proc.ObjectTable
            except exceptions.InvalidAddressException:
                vollog.log(constants.LOGLEVEL_VVV,
                           "Cannot access _EPROCESS.ObjectType at {0:#x}".format(proc.vol.offset))
                continue

            # Set of all subsections for all VADs of this process.
            # This set is used to compare against subsections from Section
            # objects, gathered via Process handles. If we find a subsection,
            # with executable memory, for a handle, not mapped in any VAD, it's
            # a hit.
            process_subsec_set = self.get_vad_subsection_set(proc)

            for i, entry in enumerate(handles.Handles(context=self.context, config_path=self.config_path).handles(object_table)):
                self._progress_callback(i, "Enumerating handles for Process {:d}".format(proc.UniqueProcessId))
                obj_name = ""
                obj_type = ""
                section_object = None
                try:
                    obj_type = entry.get_object_type(type_map, cookie)
                    if obj_type == "Section":
                        section_object = entry.Body.cast("_SECTION")
                        try:
                            obj_name = entry.NameInfo.Name.String
                        except (ValueError, exceptions.InvalidAddressException):
                            obj_name = ""
                except (exceptions.InvalidAddressException):
                    vollog.log(constants.LOGLEVEL_VVV,
                               "Cannot access _OBJECT_HEADER at {0:#x}".format(entry.vol.offset))
                    continue
                if not section_object:
                    continue

                try:
                    ca = section_object.u1.ControlArea.dereference().cast("_CONTROL_AREA")
                    if self.filter(ca):
                        continue

                    handle_subsec_set = self.enumerate_subsections(self.get_first_subsec(ca))
                    if not handle_subsec_set.difference(process_subsec_set):
                        continue

                    phys_addrs = list()
                    number_of_ptes = 0
                    for subsec_offset in handle_subsec_set:
                        subsec = self.cast_to_subsec(subsec_offset)
                        phys_addrs += self.get_phys_addrs_from_subsec(subsec)
                        number_of_ptes += subsec.PtesInSubsection

                    if self.config.get('dump_memory', True):
                        filename = "pid.{0:d}_ca.0x{1:08x}.dmp".format(
                            proc.UniqueProcessId, ca.vol.offset)
                        filedumper = interfaces.plugins.FileInterface(filename)

                        for phys_addr in phys_addrs:
                            filedumper.data.write(phys_layer.read(phys_addr, 0x1000))

                        self.produce_file(filedumper)

                    results.append((0, (proc.UniqueProcessId,
                        proc.ImageFileName.cast("string", max_length = proc.ImageFileName.vol.count,
                                                errors = 'replace'),
                        format_hints.Hex(section_object.vol.offset), format_hints.Hex(ca.vol.offset),
                        obj_name, number_of_ptes)))
                except exceptions.InvalidAddressException:
                    pass

        for result in results:
            yield result
