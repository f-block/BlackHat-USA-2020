#  Plugin to detect hidden shared memory on Linux.
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

"""This plugin detects hidden shared memory on Linux.
References:
https://dfrws.org/presentation/hiding-process-memory-via-anti-forensic-techniques/
https://www.blackhat.com/us-20/briefings/schedule/index.html#hiding-process-memory-via-anti-forensic-techniques-20661
"""

from typing import List

from volatility.framework import constants, interfaces, renderers, objects
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints
from volatility.plugins.linux import pslist
from volatility.framework.automagic import linux

def is_tmpfs_file(file_obj):
    """We are currently concentrating on tmpfs shared memory."""
    if not file_obj or not file_obj.f_mapping:
        return False
    
    # Tests file object for being S_IFREG and tmpfs
    return (file_obj.f_mapping.host.dereference().i_mode >> 12) == 8 and \
        'tmpfs' == objects.utility.array_to_string(
            file_obj.get_vfsmnt().dereference().mnt_sb.dereference().s_id)


class HiddenSharedMemory(interfaces.plugins.PluginInterface):
    """Implements the detection of hidden shared memory on Linux."""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "vmlinux", description = "Linux kernel symbols"),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
        ]


    def run(self):
        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])

        return renderers.TreeGrid([("PID", int),
                                   ("Process", str),
                                   ("file_object", format_hints.Hex),
                                   ("devname", str)],
                                  self._generator(
                                      pslist.PsList.list_tasks(self.context,
                                                               self.config['primary'],
                                                               self.config['vmlinux'],
                                                               filter_func = filter_func)))


    def _generator(self, tasks):
        symbol_table = None

        for task in tasks:
            if not task.mm:
                continue

            if symbol_table is None:
                if constants.BANG not in task.vol.type_name:
                    raise ValueError("Task is not part of a symbol table")
                symbol_table = task.vol.type_name.split(constants.BANG)[0]

            process_name = utility.array_to_string(task.comm)
            proc_file_objects = dict()
            vma_file_inodes = set()

            ### First we generate a list of all files for all vmas.
            # As the file struct instance is not unique for a given file (the 
            # file struct from a vma typically differs from the one referenced
            # by the process), we use the inode object to identify similar
            # file objects.
            for vma in task.mm.get_mmap_iter():
                if vma.vm_file:
                    vma_file_inodes.add(vma.vm_file.f_inode.dereference().vol.offset)

            ### Now we gather all shared memory objects related to the proc obj
            ### In particular, the file object instance and its inode.
            ### The inode is used for comparison with the vmas, the file object
            ### for further processing.
            # First, for memfd and mmap
            for _, file_ptr, _ in linux.LinuxUtilities.files_descriptors_for_process(
                    self.context, symbol_table, task):
                file_obj = file_ptr.dereference()
                if is_tmpfs_file(file_obj):
                    proc_file_objects[file_obj.f_inode.dereference().vol.offset] = file_obj

            # Second, all SYSTEM V type shared objects
            for shmid_kernel_obj in \
                   task.sysvshm.shm_clist.to_list(symbol_table + constants.BANG + "shmid_kernel",
                                                  "shm_clist"):
                file_obj = shmid_kernel_obj.shm_file.dereference()
                if is_tmpfs_file(file_obj):
                    proc_file_objects[file_obj.f_inode.dereference().vol.offset] = file_obj

            # Now we are diffing the two file object sets
            proc_inodes = set(proc_file_objects.keys())
            for inode in proc_inodes.difference(vma_file_inodes):
                file_obj = proc_file_objects[inode]
                yield (0, (task.pid, process_name,
                           format_hints.Hex(file_obj.vol.offset),
                           linux.LinuxUtilities.path_for_file(self.context, task, file_obj)))

