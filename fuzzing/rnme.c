#include <windows.h>
#include <stdio.h>

int main(int argc, char ** argv)
{	
	// LPSTR - A 32-bit pointer to a string of 8-bit characters, which MAY be null-terminated.
	//LPSTR command_line = GetCommandLineA();
	//printf("Command line: %s",command_line);
	char msg[100];
	memset(msg,0,100);
	// read from file
	HANDLE outfile = CreateFile("fuzzing-curr-commandline.tmp"                // name of the write
                       GENERIC_READ,    // open for writing
                       FILE_SHARE_READ,  
                       NULL,                   // default security
                       OPEN_EXISTING,          // create new file only
                       FILE_ATTRIBUTE_NORMAL,  // normal file
                       NULL);      
					// no attr. template	
	if(outfile==INVALID_FILE_HANDLE)
	{
		printf("FATAL: cannot read the current command line, the feedback channel is broken!\n");
		return -1;
	}
	int dwBytesWritten;
	int status = ReadFile(outfile, msg, 100,&dwBytesWritten,NULL);
	if(!status)
	{
		printf("FATAL: failed to read from the current command line file handle, the feedback channel is broken!\n");
		return -1;		
	}
	printf("EXECUTION ");
	printf(msg); // no newlines here please
	printf("\n");
	CloseHandle(outfile);
	return 0;
}

