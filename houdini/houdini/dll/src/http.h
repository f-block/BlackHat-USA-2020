#ifndef _REFLECTIVEDLLINJECTION_HTTP_H
#define _REFLECTIVEDLLINJECTION_HTTP_H

struct command_struct{
	char* command;
	char* buffer;
	int buffer_size;
};

command_struct send_http(char * data, LPCWSTR path);

#endif