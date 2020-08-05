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

from past.utils import old_div
from rekall.plugins import core
from rekall.plugins.linux import common
from rekall.plugins.overlays.linux import vfs


def is_tmpfs_file(file_obj):
    """We are currently concentrating on tmpfs shared memory."""
    if not file_obj:
        return False

    return file_obj.f_mapping.host.type == "S_IFREG" and \
        file_obj.vfsmnt.mnt_sb.s_id == "tmpfs"


class HiddenSharedMemoryLinux(core.DirectoryDumperMixin,
                              common.LinProcessFilter):
    """Implements the detection of hidden shared memory on Linux."""

    name = "hidden_shmem"
    dump_dir_optional = True
    default_dump_dir = None

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="task", width=12),
        dict(name="file_object", style="address", width=16),
        dict(name="devname", width=48),

    ]

    
    # taken from rekall/plugins/linux/fs.py
    def dump_file_obj(self, renderer, file_obj, filename):
        # casting file struct object to Rekall's File class
        cfile_obj = vfs.File(mountpoint=file_obj.vfsmnt,
                             dentry=file_obj.dentry,
                             is_root=True,
                             session=self.session)

        page_size = self.session.kernel_address_space.PAGE_SIZE
        buffer_size = 1024*1024
        buffer = b""

        # Write buffered output as a sparse file.
        with renderer.open(
                filename=filename,
                directory=self.dump_dir,
                mode="wb") as fd:

            for range_start, range_end in cfile_obj.extents:
                fd.seek(range_start)
                for offset in range(range_start, range_end, page_size):
                    page_index = old_div(offset, page_size)
                    to_write = min(page_size, cfile_obj.size - offset)
                    data = cfile_obj.GetPage(page_index)
                    if data != None:
                        buffer += data[:to_write]
                    else:
                        buffer += b"\x00" * to_write

                    # Dump the buffer when it's full.
                    if len(buffer) >= buffer_size:
                        fd.write(buffer)
                        buffer = b""

                # Dump the remaining data in the buffer.
                if buffer != b"":
                    fd.write(buffer)
                    buffer = b""


    def collect(self):
        cc = self.session.plugins.cc()

        for task in self.filter_processes():
            if not task.mm.dereference():
                continue

            cc.SwitchProcessContext(task)

            proc_file_objects = dict()
            vma_file_inodes = set()

            ### First we generate a list of all files for all vmas.
            # As the file struct instance is not unique for a given file (the 
            # file struct from a vma typically differs from the one referenced
            # by the process), we use the inode object to identify similar
            # file objects.
            for vma in task.mm.mmap.walk_list("vm_next"):
                if vma.vm_file:
                    vma_file_inodes.add(vma.vm_file.f_inode.deref())

            ### Now we gather all shared memory objects related to the proc obj
            ### In particular, the file object instance and its inode.
            ### The inode is used for comparison with the vmas, the file object
            ### for further processing.
            # First, for memfd and mmap
            for file_ptr in task.files.fds:
                file_obj = file_ptr.deref()
                if is_tmpfs_file(file_obj):
                    proc_file_objects[file_obj.f_inode.deref()] = file_obj

            # Second, all SYSTEM V type shared objects
            for shmid_kernel_obj in \
                    task.sysvshm.shm_clist.list_of_type("shmid_kernel",
                                                        "shm_clist"):
                file_obj = shmid_kernel_obj.shm_file.dereference()
                if is_tmpfs_file(file_obj):
                    proc_file_objects[file_obj.f_inode.deref()] = file_obj

            renderer = None
            # Now we are diffing the two file object sets
            proc_inodes = set(proc_file_objects.keys())
            for inode in proc_inodes.difference(vma_file_inodes):
                file_obj = proc_file_objects[inode]
                yield dict(task=task.pid,
                           file_object=file_obj.v(),
                           devname=task.get_path(file_obj)
                          )

                if self.dump_dir:
                    if not renderer:
                        renderer = self.session.GetRenderer()
                    filename = "pid.{:d}_file.0x{:08x}.dmp".format(task.pid,
                                                                   file_obj.v())
                    self.dump_file_obj(renderer, file_obj, filename)
                    renderer.format("Dumped content to {0}/{1}\n",
                        self.dump_dir, filename)
