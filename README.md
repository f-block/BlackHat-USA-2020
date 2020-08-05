# BlackHat-USA-2020

This is the online repository for the Talk [Hiding Process Memory via Anti-Forensic Techniques](https://www.blackhat.com/us-20/briefings/schedule/index.html#hiding-process-memory-via-anti-forensic-techniques-20661). It contains all material referenced in the talk.

The repository with the PoC implementations for all other subversion techniques and further information can be found [here](https://github.com/DFRWS-memory-subversion/DFRWS-USA-2020).

## Detection plugins

In the folder [memory_subversion_detection](memory_subversion_detection) are Rekall and Volatility3 plugins for the detection of all three subversion techniques on Linux and Windows, which also allow to dump the identified memory. The only exception is MAS Remapping detection on Linux, which is still work in progress.


For the Volatility Plugins to work just place them in the appropriate folders (volatility/framework/plugins/[linux|windows]) and use the *-h* option to get their names and options.

Depending on how the Linux profile is generated, it might be necessary to use a customized kernel module, which can be found [here](https://github.com/DFRWS-memory-subversion/DFRWS-USA-2020/blob/master/rekall_framework/tools/linux/module.c).

For Rekall, this process takes some more steps:

- Place the plugins in rekall-core/rekall/plugins/[linux|windows]
- Import the plugins in `__init__.py`
- Either use [this](https://github.com/f-block/rekall-plugins#list_plugins) plugin to list the available plugins, or look for the name field in the Python files, or use one of: ptesub\_masremap (W), ptesubversions (L), hidden\_shmem (L/W)
- For PTE subversion and MAS Remapping detection on Windows, you will also need [this](https://github.com/f-block/rekall-plugins/blob/master/README.md#ptemalfind-formerly-known-as-ptenum) plugin.
- For the Linux plugins, the same [custom kernel module](https://github.com/DFRWS-memory-subversion/DFRWS-USA-2020/blob/master/rekall_framework/tools/linux/module.c) for the profile generation is needed, as for Volatility3.
- Furthermore, [this](https://github.com/DFRWS-memory-subversion/DFRWS-USA-2020/tree/master/rekall_framework) custom Rekall version should be used.

## Shared Memory Subversion Implementation with C&C server (codename: Houdini)

Within the folder [houdini](houdini) are the source code and pre-built binaries of a shared memory subversion implementation, controllable by a C&C server.

### Workflow

On the victim side, only the executable houdini.exe is required, which is executed without any arguments. Its workflow is roughly:
- Requesting the main payload from the C&C server and loading it in a shared memory segment. The first time the DLL is mapped and started, a MessageBox pops up, indicating that execution worked fine. After that, the client will remain silent.
- The payload is periodically mapped and executed. During the rest of the time, the payload is not mapped in any virtual address space and hence, not identifyable with common detection approaches (see the talk/paper mentioned earlier), but also not directly accessible anywhere in the process' or kernel's virtual address space.
- Once mapped and executed, it contacts a configured C&C server, asks for a new tasks, and after execution, is being rehidden by the controller.

Houdini.exe is the controller, and houdini\_dll.dll the implant hidden in a shared memory segment.

The DLL contains a reflective loader, which is taken from Stephen Fewer's great [Reflective DLL Injection](https://github.com/stephenfewer/ReflectiveDLLInjection) implementation. We are, however, not injecting into another process at the moment, but only reflectively loading the DLL in a shared memory segment, simply because this comes with the advantage of writing the implant as a DLL instead of shellcode.

### Usage

While starting the executable at the victim site doesn't require anything else, the C&C server expects two files:
- The DLL (`initial_stage`).
- A command file, telling the victim what to do when it calls.

This can be accomplished by simply placing the houdini\_dll.dll and a command.json file in the C&C server's working directory.
The command.json will be re-read each time the client contacts the server for a new task.

The format of this file is:
```
{"command": "command_identifier", "payload": "potential payload, base64 encoded"}
```

The supported commands at the moment are:
- `execute_this`: Executes the given cmd and returns the result.
- `load_shellcode`: Loads the given shellcode in a separate shared memory segment; Will remain unmapped (and hence hidden) until explicitly instructed to be executed.
- `run_shellcode`: Maps the shellcode temporarily, executes it, and unmaps it afterwards. The shellcode remains loaded (but unmapped) after execution, and can be re-executed without having to load the shellcode again.
- `reveal_data`: Maps the DLL and shellcode (if loaded) for the configured amount of time (default: 60 seconds). This command is only for testing/analysis purposes. See the YARA section later.

Some example command.json files are provided in the [cnc_server](houdini/cnc_server) folder.

The steps to e.g. load and execute a custom shellcode is as follows:
```
# start houdini.exe at the victim

# start cnc_server.py at the server
python3 cnc_server.py

cp command.json_loadshell command.json

# Wait for client to fetch and load the payload. The log message on the server should say something like: 
# [+] Received some data from client:
# Shellcode loaded successfully.

# Now we can instruct the victim to execute our shellcode:
cp command.json_runshell command.json
```

### Detection

The DLL and the [example shellcode](houdini/cnc_server/command.json_loadshellcode) each contain a unique token, which can be detected with the [token.yar](houdini/token.yar) YARA rule file, as long as they are currently mapped:
- The DLL: `BLACKHAT_USA_2020_what.the.eyes.see.and.the.ears.hear..the.mind.believes_BLACKHAT_USA_2020`
- The Shellcode: `AAAAAAAAAAAAAAAAAA_what.the.eyes.see.and.the.ears.hear..the.mind.believes_AAAAAAAAAAAAAAAAAA`

The tokens should, however, only be detectable in one of the following cases:
- As long as a MessageBox is shown.
- When using the `reveal_data` command.
- When we are lucky and catch the memory while being mapped (e.g. when the DLL/shellcode is currently executed).

Otherwise, the memory should be hidden and a YARA scan shouldn't have a hit. If you experience otherwise, let me know ;-) (bhusa2020 at f-block.org)

To detect and dump the hidden memory despite being hidden, try the Volatility3/Rekall plugins: [memory\_subversion\_detection](memory_subversion_detection)


### Configuration

To adjust some central configuration options, use the [houdini.h](houdini/houdini/dll/src/houdini.h) header file (e.g. the C&C server address).
The [pre-built binaries](houdini/houdini/x64/Release) are trying to reach the C&C server at: `http://192.168.56.1:8000`
There is also a debug version of the controller and DLL ([houdini.debug.exe](houdini/houdini/x64/Release/houdini.debug.exe) and [houdini\_dll.debug.dll](houdini/houdini/x64/Release/houdini_dll.debug.dll)), which will print most of the stuff going on at the cmd line, and also uses MessageBoxes. For Debug builds see also [houdini.h](houdini/houdini/dll/src/houdini.h).

### TODOs

- [ ] Minimizing the memory footprint (see below).
- [ ] Making Houdini injectable.


Despite the communication between client and server being encrypted, there are still identifyable artifacts in memory, which should be cleaned by erasing them after usage.

But more important: While the DLL and shellcode are hidden, the controller, which loads the DLL and un/rehides it, still is detectable. One way to minimize that would be erasing all code from the controller during runtime, except the part for the un/rehiding.

A better way would, however, be using the cool trick from Joseph Lospinoso's [Gargoyle](https://github.com/JLospinoso/gargoyle): A timer and a ROP chain to unhide and execute the DLL and by that, getting rid of the controller.
