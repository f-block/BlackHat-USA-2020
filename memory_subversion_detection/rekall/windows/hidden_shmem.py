#  Plugin to detect hidden executable shared memory on Windows.
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

from rekall_lib import utils
from rekall.plugins import core
from rekall.plugins.windows import common


def get_vad_subsection_set(task):
    """Returns all SUBSECTIONs for all VADs for a given process."""
    subsec_set = set()

    for vadd in task.RealVadRoot.traverse():
        if vadd.m('Subsection'):
            for subsec in vadd.Subsection.walk_list('NextSubsection'):
                subsec_set.add(subsec)

    return subsec_set


def get_ca_filename(control_area):
    filename = ""
    try:
        file_obj = control_area.FilePointer
        if file_obj:
            filename = (file_obj.file_name_with_drive() or
                        "Pagefile-backed section")
    except AttributeError:
        pass

    if not filename:
        return 'Pagefile-backed section'
    
    return str(filename)


def ca_contains_image_file(control_area):
    """Returns True if CONTROL_AREA belongs to a mapped Image file."""

    try:
        sec_obj_poi = control_area.FilePointer.SectionObjectPointer
        if sec_obj_poi.ImageSectionObject:
            return True
    except AttributeError:
        pass

    return False


class HiddenSharedMemory(core.DirectoryDumperMixin, common.WinProcessFilter):
    """Implements the detection of hidden executable shared memory
    on Windows."""

    name = "hidden_shmem"
    dump_dir_optional = True
    default_dump_dir = None

    table_header = [
        dict(name='task', width=12),
        dict(name='section_object', style="address", width=16),
        dict(name='Control_Area', style="address", width=16),
        dict(name='handle_name', width=30),
        dict(name='number_of_pages', width=12),
        dict(name='filename')
    ]

    def filter(self, control_area):
        """Returns True if the CONTROL_AREA should be ignored."""

        if ca_contains_image_file(control_area):
            return True

        firstsubsection = control_area.FirstSubsection
        for subsection in firstsubsection.walk_list('NextSubsection'):
            if 'EXECUTE' in str(subsection.u.SubsectionFlags.ProtectionEnum):
                return False

        return True


    def collect(self):
        cc = self.session.plugins.cc()
        handlesplugin = self.session.plugins.handles()

        for task in self.filter_processes():
            task_as = task.get_process_address_space()
            if not task_as or task_as == self.session.kernel_address_space:
                continue

            cc.SwitchProcessContext(task)

            process_subsec_set = get_vad_subsection_set(task)
            for handle, object_type, name in \
                    handlesplugin.enumerate_handles(task):
                if not object_type == "Section":
                    continue

                if self.session.profile.metadata("major", 0) >= 10:
                    # Windows 10
                    section_object = handle.Body.cast("_SECTION")
                    control_area = section_object.u1.ControlArea
                else:
                    # only tested with Windows 7
                    section_object = handle.Body.cast("_SECTION_OBJECT")
                    control_area = self.session.profile._CONTROL_AREA(
                        offset=section_object.Segment.BaseAddress.v())

                if self.filter(control_area):
                    continue

                handle_subsec_set = set()
                firstsubsection = control_area.FirstSubsection
                proto_ptes = list()
                number_of_ptes = 0
                for subsection in firstsubsection.walk_list('NextSubsection'):
                    proto_ptes.append((subsection.StartingSector,
                                       [x for x in subsection.SubsectionBase]))
                    handle_subsec_set.add(subsection)
                    number_of_ptes += subsection.PtesInSubsection

                if not handle_subsec_set.difference(process_subsec_set):
                    continue

                yield dict(
                    task=task.pid,
                    section_object=section_object.v(),
                    Control_Area=control_area.v(),
                    handle_name=name,
                    number_of_pages=number_of_ptes,
                    filename=get_ca_filename(control_area)
                )

                if self.dump_dir:
                    renderer = self.session.GetRenderer()
                    filename = "pid.{0:d}_ca.0x{1:08x}_handle.{2}.dmp".format(
                        task.pid, control_area.v(), name)
            
                    with renderer.open(directory=self.dump_dir,
                                       filename=filename,
                                       mode='wb') as fd:
                        self.session.report_progress("Dumping %s" % filename)
        
                        for proto_pte in [x for _, y in sorted(proto_ptes, key=lambda z: z[0]) for x in y]:
                            phys_addr = self.session.kernel_address_space.ResolveProtoPTE(proto_pte.Long, 0)
                            if phys_addr:
                                fd.write(self.session.physical_address_space.read(phys_addr, 0x1000))
                    renderer.format("Dumped content to {0}/{1}\n", self.dump_dir, filename)
