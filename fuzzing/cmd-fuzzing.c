// The goal of this is to dynamically test how cmd.exe handles input from functions like CreateProcessA()/Shellexec, to highlight any potential vectors for a universal command injection vulnerability.
// This general meta-PoC application explores all the attack vectors desribed in ATTACK_VECTORS.txt.

// COMBINATORICS:
// we should retest the following combinations:
// with both space and without space after whoami * ALL quote syntaxes INCLUDING quote mixing * all /c /K and other switches (maybe where are some hidden as well) * multiple characters 

// Multiple characters involves:
// - wide ascii/UTF
// - double characters (as per the documentation, && works as a command separator in quoted strings, maybe there's something else that does?)

// At this point the only practical problem that remains is the ever-growing memory use even through there are no malloc() calls. The easiest workaround might be to split these tests into separate per-command line series.
	
// Successfully compiled & run with Dev CPP on Win10 x64.
// "C:\Program Files (x86)\Dev-Cpp\MinGW64\bin\gcc.exe" "C:\Users\ewilded\HACKING\SHELLING\research\cmd.exe\fuzzing\fuzzing.c" -o "C:\Users\ewilded\HACKING\SHELLING\research\cmd.exe\fuzzing\fuzzing.exe"  -I"C:\Program Files (x86)\Dev-Cpp\MinGW64\include" -I"C:\Program Files (x86)\Dev-Cpp\MinGW64\x86_64-w64-mingw32\include" -I"C:\Program Files (x86)\Dev-Cpp\MinGW64\lib\gcc\x86_64-w64-mingw32\4.9.2\include" -I"C:\Users\ewilded\TOOLS\openssl\openssl-0.9.8h-1-lib\include" -L"C:\Program Files (x86)\Dev-Cpp\MinGW64\lib" -L"C:\Program Files (x86)\Dev-Cpp\MinGW64\x86_64-w64-mingw32\lib" -static-libgcc

//
#include <windows.h>
#include <string.h>
#include <stdio.h>

char * templates[] = {"/c \"rnme ABwhoami\"", "/c \"rnme ABwhoami'", "/c \"rnmeABwhoami\"", "/c \"rnmeABwhoami'", "/c 'rnme ABwhoami\"", "/c 'rnme ABwhoami'", "/c 'rnmeABwhoami\"", "/c 'rnmeABwhoami'", "/c rnme ABwhoami\"", "/c rnme ABwhoami'", "/c rnmeABwhoami\"", "/c rnmeABwhoami'", "/c \"rnme ABwhoamiC", "/c \"rnmeABwhoamiC", "/c 'rnme ABwhoamiC", "/c 'rnmeABwhoamiC", "/c rnme ABwhoamiC", "/c rnmeABwhoamiC", "/c \"rnme ABwhoamiCD", "/c \"rnmeABwhoamiCD", "/c 'rnme ABwhoamiCD", "/c 'rnmeABwhoamiCD", "/c rnme ABwhoamiCD", "/c rnmeABwhoamiCD", "/c \"rnme ABwhoami\"D", "/c \"rnme ABwhoami'D", "/c \"rnmeABwhoami\"D", "/c \"rnmeABwhoami'D", "/c 'rnme ABwhoami\"D", "/c 'rnme ABwhoami'D", "/c 'rnmeABwhoami\"D", "/c 'rnmeABwhoami'D", "/c rnme ABwhoami\"D", "/c rnme ABwhoami'D", "/c rnmeABwhoami\"D", "/c rnmeABwhoami'D", "/c \"rnme Awhoami\"", "/c \"rnme Awhoami'", "/c \"rnmeAwhoami\"", "/c \"rnmeAwhoami'", "/c 'rnme Awhoami\"", "/c 'rnme Awhoami'", "/c 'rnmeAwhoami\"", "/c 'rnmeAwhoami'", "/c rnme Awhoami\"", "/c rnme Awhoami'", "/c rnmeAwhoami\"", "/c rnmeAwhoami'", "/c \"rnme AwhoamiC", "/c \"rnmeAwhoamiC", "/c 'rnme AwhoamiC", "/c 'rnmeAwhoamiC", "/c rnme AwhoamiC", "/c rnmeAwhoamiC", "/c \"rnme AwhoamiCD", "/c \"rnmeAwhoamiCD", "/c 'rnme AwhoamiCD", "/c 'rnmeAwhoamiCD", "/c rnme AwhoamiCD", "/c rnmeAwhoamiCD", "/c \"rnme Awhoami\"D", "/c \"rnme Awhoami'D", "/c \"rnmeAwhoami\"D", "/c \"rnmeAwhoami'D", "/c 'rnme Awhoami\"D", "/c 'rnme Awhoami'D", "/c 'rnmeAwhoami\"D", "/c 'rnmeAwhoami'D", "/c rnme Awhoami\"D", "/c rnme Awhoami'D", "/c rnmeAwhoami\"D", "/c rnmeAwhoami'D", "/c \"rnme \"Bwhoami\"", "/c \"rnme \"Bwhoami'", "/c \"rnme 'Bwhoami\"", "/c \"rnme 'Bwhoami'", "/c \"rnme\"Bwhoami\"", "/c \"rnme\"Bwhoami'", "/c \"rnme'Bwhoami\"", "/c \"rnme'Bwhoami'", "/c 'rnme \"Bwhoami\"", "/c 'rnme \"Bwhoami'", "/c 'rnme 'Bwhoami\"", "/c 'rnme 'Bwhoami'", "/c 'rnme\"Bwhoami\"", "/c 'rnme\"Bwhoami'", "/c 'rnme'Bwhoami\"", "/c 'rnme'Bwhoami'", "/c rnme \"Bwhoami\"", "/c rnme \"Bwhoami'", "/c rnme 'Bwhoami\"", "/c rnme 'Bwhoami'", "/c rnme\"Bwhoami\"", "/c rnme\"Bwhoami'", "/c rnme'Bwhoami\"", "/c rnme'Bwhoami'", "/c \"rnme \"BwhoamiC", "/c \"rnme 'BwhoamiC", "/c \"rnme\"BwhoamiC", "/c \"rnme'BwhoamiC", "/c 'rnme \"BwhoamiC", "/c 'rnme 'BwhoamiC", "/c 'rnme\"BwhoamiC", "/c 'rnme'BwhoamiC", "/c rnme \"BwhoamiC", "/c rnme 'BwhoamiC", "/c rnme\"BwhoamiC", "/c rnme'BwhoamiC", "/c \"rnme \"BwhoamiCD", "/c \"rnme 'BwhoamiCD", "/c \"rnme\"BwhoamiCD", "/c \"rnme'BwhoamiCD", "/c 'rnme \"BwhoamiCD", "/c 'rnme 'BwhoamiCD", "/c 'rnme\"BwhoamiCD", "/c 'rnme'BwhoamiCD", "/c rnme \"BwhoamiCD", "/c rnme 'BwhoamiCD", "/c rnme\"BwhoamiCD", "/c rnme'BwhoamiCD", "/c \"rnme \"Bwhoami\"D", "/c \"rnme \"Bwhoami'D", "/c \"rnme 'Bwhoami\"D", "/c \"rnme 'Bwhoami'D", "/c \"rnme\"Bwhoami\"D", "/c \"rnme\"Bwhoami'D", "/c \"rnme'Bwhoami\"D", "/c \"rnme'Bwhoami'D", "/c 'rnme \"Bwhoami\"D", "/c 'rnme \"Bwhoami'D", "/c 'rnme 'Bwhoami\"D", "/c 'rnme 'Bwhoami'D", "/c 'rnme\"Bwhoami\"D", "/c 'rnme\"Bwhoami'D", "/c 'rnme'Bwhoami\"D", "/c 'rnme'Bwhoami'D", "/c rnme \"Bwhoami\"D", "/c rnme \"Bwhoami'D", "/c rnme 'Bwhoami\"D", "/c rnme 'Bwhoami'D", "/c rnme\"Bwhoami\"D", "/c rnme\"Bwhoami'D", "/c rnme'Bwhoami\"D", "/c rnme'Bwhoami'D", "/c \"rnme \"whoami\"", "/c \"rnme \"whoami'", "/c \"rnme 'whoami\"", "/c \"rnme 'whoami'", "/c \"rnme\"whoami\"", "/c \"rnme\"whoami'", "/c \"rnme'whoami\"", "/c \"rnme'whoami'", "/c 'rnme \"whoami\"", "/c 'rnme \"whoami'", "/c 'rnme 'whoami\"", "/c 'rnme 'whoami'", "/c 'rnme\"whoami\"", "/c 'rnme\"whoami'", "/c 'rnme'whoami\"", "/c 'rnme'whoami'", "/c rnme \"whoami\"", "/c rnme \"whoami'", "/c rnme 'whoami\"", "/c rnme 'whoami'", "/c rnme\"whoami\"", "/c rnme\"whoami'", "/c rnme'whoami\"", "/c rnme'whoami'", "/c \"rnme \"whoamiC", "/c \"rnme 'whoamiC", "/c \"rnme\"whoamiC", "/c \"rnme'whoamiC", "/c 'rnme \"whoamiC", "/c 'rnme 'whoamiC", "/c 'rnme\"whoamiC", "/c 'rnme'whoamiC", "/c rnme \"whoamiC", "/c rnme 'whoamiC", "/c rnme\"whoamiC", "/c rnme'whoamiC", "/c \"rnme \"whoamiCD", "/c \"rnme 'whoamiCD", "/c \"rnme\"whoamiCD", "/c \"rnme'whoamiCD", "/c 'rnme \"whoamiCD", "/c 'rnme 'whoamiCD", "/c 'rnme\"whoamiCD", "/c 'rnme'whoamiCD", "/c rnme \"whoamiCD", "/c rnme 'whoamiCD", "/c rnme\"whoamiCD", "/c rnme'whoamiCD", "/c \"rnme \"whoami\"D", "/c \"rnme \"whoami'D", "/c \"rnme 'whoami\"D", "/c \"rnme 'whoami'D", "/c \"rnme\"whoami\"D", "/c \"rnme\"whoami'D", "/c \"rnme'whoami\"D", "/c \"rnme'whoami'D", "/c 'rnme \"whoami\"D", "/c 'rnme \"whoami'D", "/c 'rnme 'whoami\"D", "/c 'rnme 'whoami'D", "/c 'rnme\"whoami\"D", "/c 'rnme\"whoami'D", "/c 'rnme'whoami\"D", "/c 'rnme'whoami'D", "/c rnme \"whoami\"D", "/c rnme \"whoami'D", "/c rnme 'whoami\"D", "/c rnme 'whoami'D", "/c rnme\"whoami\"D", "/c rnme\"whoami'D", "/c rnme'whoami\"D", "/c rnme'whoami'D"};
	//"/r \"whoami ABrnme\"", "/r \"whoami ABrnme'", "/r \"whoamiABrnme\"", "/r \"whoamiABrnme'", "/r 'whoami ABrnme\"", "/r 'whoami ABrnme'", "/r 'whoamiABrnme\"", "/r 'whoamiABrnme'", "/r whoami ABrnme\"", "/r whoami ABrnme'", "/r whoamiABrnme\"", "/r whoamiABrnme'", "/r \"whoami ABrnmeC", "/r \"whoamiABrnmeC", "/r 'whoami ABrnmeC", "/r 'whoamiABrnmeC", "/r whoami ABrnmeC", "/r whoamiABrnmeC", "/r \"whoami ABrnmeCD", "/r \"whoamiABrnmeCD", "/r 'whoami ABrnmeCD", "/r 'whoamiABrnmeCD", "/r whoami ABrnmeCD", "/r whoamiABrnmeCD", "/r \"whoami ABrnme\"D", "/r \"whoami ABrnme'D", "/r \"whoamiABrnme\"D", "/r \"whoamiABrnme'D", "/r 'whoami ABrnme\"D", "/r 'whoami ABrnme'D", "/r 'whoamiABrnme\"D", "/r 'whoamiABrnme'D", "/r whoami ABrnme\"D", "/r whoami ABrnme'D", "/r whoamiABrnme\"D", "/r whoamiABrnme'D", "/r \"whoami Arnme\"", "/r \"whoami Arnme'", "/r \"whoamiArnme\"", "/r \"whoamiArnme'", "/r 'whoami Arnme\"", "/r 'whoami Arnme'", "/r 'whoamiArnme\"", "/r 'whoamiArnme'", "/r whoami Arnme\"", "/r whoami Arnme'", "/r whoamiArnme\"", "/r whoamiArnme'", "/r \"whoami ArnmeC", "/r \"whoamiArnmeC", "/r 'whoami ArnmeC", "/r 'whoamiArnmeC", "/r whoami ArnmeC", "/r whoamiArnmeC", "/r \"whoami ArnmeCD", "/r \"whoamiArnmeCD", "/r 'whoami ArnmeCD", "/r 'whoamiArnmeCD", "/r whoami ArnmeCD", "/r whoamiArnmeCD", "/r \"whoami Arnme\"D", "/r \"whoami Arnme'D", "/r \"whoamiArnme\"D", "/r \"whoamiArnme'D", "/r 'whoami Arnme\"D", "/r 'whoami Arnme'D", "/r 'whoamiArnme\"D", "/r 'whoamiArnme'D", "/r whoami Arnme\"D", "/r whoami Arnme'D", "/r whoamiArnme\"D", "/r whoamiArnme'D", "/r \"whoami \"Brnme\"", "/r \"whoami \"Brnme'", "/r \"whoami 'Brnme\"", "/r \"whoami 'Brnme'", "/r \"whoami\"Brnme\"", "/r \"whoami\"Brnme'", "/r \"whoami'Brnme\"", "/r \"whoami'Brnme'", "/r 'whoami \"Brnme\"", "/r 'whoami \"Brnme'", "/r 'whoami 'Brnme\"", "/r 'whoami 'Brnme'", "/r 'whoami\"Brnme\"", "/r 'whoami\"Brnme'", "/r 'whoami'Brnme\"", "/r 'whoami'Brnme'", "/r whoami \"Brnme\"", "/r whoami \"Brnme'", "/r whoami 'Brnme\"", "/r whoami 'Brnme'", "/r whoami\"Brnme\"", "/r whoami\"Brnme'", "/r whoami'Brnme\"", "/r whoami'Brnme'", "/r \"whoami \"BrnmeC", "/r \"whoami 'BrnmeC", "/r \"whoami\"BrnmeC", "/r \"whoami'BrnmeC", "/r 'whoami \"BrnmeC", "/r 'whoami 'BrnmeC", "/r 'whoami\"BrnmeC", "/r 'whoami'BrnmeC", "/r whoami \"BrnmeC", "/r whoami 'BrnmeC", "/r whoami\"BrnmeC", "/r whoami'BrnmeC", "/r \"whoami \"BrnmeCD", "/r \"whoami 'BrnmeCD", "/r \"whoami\"BrnmeCD", "/r \"whoami'BrnmeCD", "/r 'whoami \"BrnmeCD", "/r 'whoami 'BrnmeCD", "/r 'whoami\"BrnmeCD", "/r 'whoami'BrnmeCD", "/r whoami \"BrnmeCD", "/r whoami 'BrnmeCD", "/r whoami\"BrnmeCD", "/r whoami'BrnmeCD", "/r \"whoami \"Brnme\"D", "/r \"whoami \"Brnme'D", "/r \"whoami 'Brnme\"D", "/r \"whoami 'Brnme'D", "/r \"whoami\"Brnme\"D", "/r \"whoami\"Brnme'D", "/r \"whoami'Brnme\"D", "/r \"whoami'Brnme'D", "/r 'whoami \"Brnme\"D", "/r 'whoami \"Brnme'D", "/r 'whoami 'Brnme\"D", "/r 'whoami 'Brnme'D", "/r 'whoami\"Brnme\"D", "/r 'whoami\"Brnme'D", "/r 'whoami'Brnme\"D", "/r 'whoami'Brnme'D", "/r whoami \"Brnme\"D", "/r whoami \"Brnme'D", "/r whoami 'Brnme\"D", "/r whoami 'Brnme'D", "/r whoami\"Brnme\"D", "/r whoami\"Brnme'D", "/r whoami'Brnme\"D", "/r whoami'Brnme'D", "/r \"whoami \"rnme\"", "/r \"whoami \"rnme'", "/r \"whoami 'rnme\"", "/r \"whoami 'rnme'", "/r \"whoami\"rnme\"", "/r \"whoami\"rnme'", "/r \"whoami'rnme\"", "/r \"whoami'rnme'", "/r 'whoami \"rnme\"", "/r 'whoami \"rnme'", "/r 'whoami 'rnme\"", "/r 'whoami 'rnme'", "/r 'whoami\"rnme\"", "/r 'whoami\"rnme'", "/r 'whoami'rnme\"", "/r 'whoami'rnme'", "/r whoami \"rnme\"", "/r whoami \"rnme'", "/r whoami 'rnme\"", "/r whoami 'rnme'", "/r whoami\"rnme\"", "/r whoami\"rnme'", "/r whoami'rnme\"", "/r whoami'rnme'", "/r \"whoami \"rnmeC", "/r \"whoami 'rnmeC", "/r \"whoami\"rnmeC", "/r \"whoami'rnmeC", "/r 'whoami \"rnmeC", "/r 'whoami 'rnmeC", "/r 'whoami\"rnmeC", "/r 'whoami'rnmeC", "/r whoami \"rnmeC", "/r whoami 'rnmeC", "/r whoami\"rnmeC", "/r whoami'rnmeC", "/r \"whoami \"rnmeCD", "/r \"whoami 'rnmeCD", "/r \"whoami\"rnmeCD", "/r \"whoami'rnmeCD", "/r 'whoami \"rnmeCD", "/r 'whoami 'rnmeCD", "/r 'whoami\"rnmeCD", "/r 'whoami'rnmeCD", "/r whoami \"rnmeCD", "/r whoami 'rnmeCD", "/r whoami\"rnmeCD", "/r whoami'rnmeCD", "/r \"whoami \"rnme\"D", "/r \"whoami \"rnme'D", "/r \"whoami 'rnme\"D", "/r \"whoami 'rnme'D", "/r \"whoami\"rnme\"D", "/r \"whoami\"rnme'D", "/r \"whoami'rnme\"D", "/r \"whoami'rnme'D", "/r 'whoami \"rnme\"D", "/r 'whoami \"rnme'D", "/r 'whoami 'rnme\"D", "/r 'whoami 'rnme'D", "/r 'whoami\"rnme\"D", "/r 'whoami\"rnme'D", "/r 'whoami'rnme\"D", "/r 'whoami'rnme'D", "/r whoami \"rnme\"D", "/r whoami \"rnme'D", "/r whoami 'rnme\"D", "/r whoami 'rnme'D", "/r whoami\"rnme\"D", "/r whoami\"rnme'D", "/r whoami'rnme\"D", "/r whoami'rnme'D"
	
	//char * templates[] = {"/c \"whoamiArnme\""};

// this is the range for single-byte fuzzing - alnum are skipped to reduce the junk results, thus a fixed array instead of just range in an array

byte fuzz_bytes[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 91, 92, 93, 94, 95, 96, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254}; // up to 255

// we want to write interesting results into a file instead of the stdout (too high volume and cmd.exe does not handle it well - mem use keeps growing - when output is simply redirected into a file with > )
HANDLE outfile;

void runCmdA(LPSTR appname, LPSTR command_line, const char * command_template, int * indexbytes)
{
	//printf("Trying %s (%s)\n", command_template, (char *)command_line);
	int slen = strlen(command_template);
	int i;
	char debug_buff[21]; // max 4*5 bytes +  nullbyte
	memset(debug_buff,0,21);
	char curr_buff[6]; // max 5 bytes + nullbyte
	memset(curr_buff,0,6);
	for(i=0;i<slen;i++)
	{
		if(command_template[i]=='A')
		{
			snprintf(curr_buff,5,"[%u]",(byte)command_line[indexbytes[0]]);
			strcat(debug_buff,curr_buff);
			memset(curr_buff,0,6);
		}
		if(command_template[i]=='B')
		{
			snprintf(curr_buff,5,"[%u]",(byte)command_line[indexbytes[1]]);
			strcat(debug_buff,curr_buff);
			memset(curr_buff,0,6);
		}
		if(command_template[i]=='C')
		{
			snprintf(curr_buff,5,"[%u]",(byte)command_line[indexbytes[2]]);
			strcat(debug_buff,curr_buff);
			memset(curr_buff,0,6);
		}
		if(command_template[i]=='D')
		{
			snprintf(curr_buff,5,"[%u]",(byte)command_line[indexbytes[3]]);
			strcat(debug_buff,curr_buff);
			memset(curr_buff,0,6);
		}
	}
	
	// this should go up, before the execution
	char msg[60]; // command line up to 28 chars + space + debug_buff up to 20, + space + EXEC\+ nullbyte  -> 57
	memset(msg,0,60);
	strcat(msg,command_template);
	strcat(msg," ");
	strcat(msg,debug_buff);
	strcat(msg," ");
	// OK, this needs to be written to the fuzzing-curr-commandline.tmp file now
	HANDLE feedback_file = CreateFileA("fuzzing-curr-commandline.tmp",  // name of the write
        GENERIC_WRITE,    // open for reading & writing
        FILE_SHARE_READ,               
        NULL,                   // default security
        CREATE_ALWAYS,          // create new file only
        FILE_ATTRIBUTE_NORMAL,  // normal file
    NULL);                  // no attr. template
	if(feedback_file==INVALID_HANDLE_VALUE)
	{
		printf("FATAL ERROR: cannot create the fuzzing-curr-template.tmp feedback channel file! Exiting.");
		return;
	}
	DWORD dwBytesToWrite = (DWORD)strlen(msg);			
	DWORD dwBytesWritten = 0;
	if(!WriteFile(feedback_file, // open file handle
        msg,      // start of data to write
        dwBytesToWrite,  // number of bytes to write
        &dwBytesWritten, // number of bytes that were written
        NULL))
	{
		printf("FATAL ERROR: cannot writ the fuzzing-curr-template.tmp feedback channel file! Exiting.");
		return;
	}
	CloseHandle(feedback_file);
	
	// Interestingly, this returns ERROR_FILE_NOT_FOUND when "cmd.exe" is provided without the full path
    PROCESS_INFORMATION pi; 
	// taken from https://stackoverflow.com/questions/10866944/how-can-i-read-a-child-processs-output
	SECURITY_ATTRIBUTES sAttr;
	memset(&sAttr, 0, sizeof(sAttr));
	sAttr.nLength = sizeof(SECURITY_ATTRIBUTES); 
	sAttr.bInheritHandle = TRUE; 
	sAttr.lpSecurityDescriptor = NULL;
	HANDLE stdoutReadHandle = NULL;
    HANDLE stdoutWriteHandle = NULL;
	STARTUPINFOA si; 
    memset(&si, 0, sizeof(si)); 
    si.cb = sizeof(si); 
    si.dwFlags |= STARTF_USESTDHANDLES;
    LPSTARTUPINFOA si_w = (LPSTARTUPINFOA) &si;
    char outbuf[32768];
    DWORD bytes_read;
    char tBuf[257];

	// OK, we need to read the child process output, GetLastError() is not sufficient to determine whether the command was valid or not - whether the command injection/whatever would be successful.
	// Create a pipe for the child process's STDOUT. 
	if (!CreatePipe(&stdoutReadHandle, &stdoutWriteHandle, &sAttr, 5000)) // 5000 is the suggested buffer size
	{
		printf("CreatePipe: %u\n", GetLastError());
		return;
	}
	// Ensure the read handle to the pipe for STDOUT is not inherited.
	if (!SetHandleInformation(stdoutReadHandle, HANDLE_FLAG_INHERIT, 0))
	{
		printf("SetHandleInformation: %u\n", GetLastError());
		return;
	}
	si.hStdError = stdoutWriteHandle;
	si.hStdOutput = stdoutWriteHandle;
	si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);		
	bytes_read=0;	
	memset(outbuf,0,32768);
	memset(tBuf,0,257);	
	int proc = CreateProcessA(appname, command_line, 0, 0, TRUE, NORMAL_PRIORITY_CLASS, NULL, NULL, si_w, &pi);
	if(proc==0)
	{
		printf("We're doing it wrong: GetLastError() returned %u.\n", GetLastError()); // For example: GetLastError() returning 2 means ERROR_FILE_NOT_FOUND
	}
	else
	{
		CloseHandle(stdoutWriteHandle); // printf("Retrieving status of the child process...");
		DWORD exit_code = NULL;
		GetExitCodeProcess(pi.hProcess, &exit_code); //printf("Process status: %d\n", exit_code); // 259 - which according to https://www.symantec.com/connect/articles/windows-system-error-codes-exit-codes-description means "No more data is available"..
		strcpy_s(outbuf, sizeof(outbuf), "");
		for (;;) 
		{
			//109 (ERROR_BROKEN_PIPE) is normal here
			//printf("Attempting to read from the output...\n");
			if (!ReadFile(stdoutReadHandle, tBuf, 256, &bytes_read, NULL))
			{
			//	printf("ReadFile GetLastError(): %u.\n", GetLastError());
				break;
			}
			//printf("Just after ReadFile, read %u byte(s)\n", bytes_read);
			if (bytes_read > 0)
			{
				tBuf[bytes_read] = '\0';
				strcat_s(outbuf, sizeof(outbuf), tBuf);
			}
		}

		
		int rn_exec = 0; // rn exec only means that the first command executed (mildly interesting)
		int whoami_exec = 0; // whoami exec means that the injected command executed (more interesting)
		
		if(strstr(outbuf,"EXECUTION")) rn_exec=1;		
		if(strstr(outbuf,"desktop")) whoami_exec=1;

		if(whoami_exec||rn_exec)
		{
			if(whoami_exec) strcat(msg,"EXEC"); // indicates the second command executed (rnme), which is far more interesting
			if(rn_exec) strcat(msg,"+"); // just indicates that the first command executed, helpful for studying different syntax approaches
			strcat(msg,"\n");
			dwBytesToWrite = (DWORD)strlen(msg);
			// now, the report file

			WriteFile( 
                    outfile,           // open file handle
                    msg,      // start of data to write
                    dwBytesToWrite,  // number of bytes to write
                    &dwBytesWritten, // number of bytes that were written
                    NULL);
			printf(msg);
		}
		
		if (WaitForSingleObject(pi.hProcess, 5000) != WAIT_OBJECT_0)	// wait up to five seconds
		{
			//printf("WaitForSingleObject GetLastError(): %u.\n", GetLastError());
			return;
		}
		if (!GetExitCodeProcess(pi.hProcess, &exit_code)) // We should terminate all the processes that did not exit within the 5000 milisecond window
		{
			//printf("GetExitCodeProcess GetLastError(): %u.\n", GetLastError());
			return;
		}
		return;
	}
}
// this function takes one param: the command_line template string (the general syntax), locates the index of the "A" letter and does fuzzing by automatically replacing it with payloads
void fuzzABCD(char * command_line) 
{
	printf("[FUZZING] %s\n", command_line);
	LPSTR appname ="C:\\Windows\\system32\\cmd.exe";
	char buff[100];
	memset(buff,0,100);
	strcpy(buff,command_line); // wink buffer overflow wink ;]
	// unless we are doing multibyte, we do not need to iterate over the full ASCII range
	// (we can skip digits and letters)	
	// find A position
	int indexABCD[] = {0,0,0,0};
	
	const char * positionA = strstr(buff,"A");
	const char * positionB = strstr(buff,"B");
	const char * positionC = strstr(buff,"C");
	const char * positionD = strstr(buff,"D");
	
	if(positionA!=NULL)	indexABCD[0] = positionA-buff;	
	if(positionB!=NULL)	indexABCD[1] = positionB-buff;
	if(positionC!=NULL)	indexABCD[2] = positionC-buff;
	if(positionD!=NULL)	indexABCD[3] = positionD-buff;

	byte i = 0;
	byte j = 0;
	byte k = 0;
	byte l = 0;

	if(positionA!=NULL)
	{
		for(i=0;i<203;i++)
		{
			buff[indexABCD[0]] = fuzz_bytes[i]; 
			if(positionB!=NULL)
			{
				for(j=0;j<203;j++)
				{
					buff[indexABCD[1]] = fuzz_bytes[j];
					if(positionC!=NULL)
					{
						for(k=0;k<203;k++)
						{
							buff[indexABCD[2]] = fuzz_bytes[k];
							if(positionD!=NULL)
							{
								for(l=0;l<203;l++)
								{
									buff[indexABCD[3]] = fuzz_bytes[l];
									runCmdA(appname, buff, command_line, indexABCD); 
								}
							}
							else
							{
								runCmdA(appname, buff, command_line, indexABCD);
							}
						}
					}
					else
					{
						runCmdA(appname, buff, command_line, indexABCD);
					}
 				}
			}	// the code above looks good
			else
			{	// position B is null
				if(positionC!=NULL)
				{
					for(k=0;k<203;k++)
					{
						buff[indexABCD[2]] = fuzz_bytes[k];
						if(positionD!=NULL)
						{
							for(l=0;l<203;l++)
							{
								buff[indexABCD[3]] = fuzz_bytes[l];
								runCmdA(appname, buff, command_line, indexABCD);	
							}
						}
						else
						{	// position D is NULL, we're done here
							runCmdA(appname, buff, command_line, indexABCD);
						}
					}
 				}
				else
				{
					if(positionD!=NULL)
					{
						for(l=0;l<203;l++)
						{
							buff[indexABCD[3]] = fuzz_bytes[l];
							runCmdA(appname, buff, command_line, indexABCD);	
						}
					}
					else
					{	// position D is NULL, we're done here
						runCmdA(appname, buff, command_line, indexABCD);
					}
				}
			} // the code above looks good
		}
	} // the code above looks good
	else
	{	// so we know A is null here, now just copy-paste of the logic from the for loop from under A
		if(positionB!=NULL)
		{
			for(j=0;j<203;j++)
			{
				buff[indexABCD[1]] = fuzz_bytes[j];
				if(positionC!=NULL)
				{
					for(k=0;k<203;k++)
					{
						buff[indexABCD[2]] = fuzz_bytes[k];
						if(positionD!=NULL)
						{
							for(l=0;l<203;l++)
							{
								buff[indexABCD[3]] = fuzz_bytes[l];
								runCmdA(appname, buff, command_line, indexABCD); 
							}
						}
						else
						{
							runCmdA(appname, buff, command_line, indexABCD);
						}
					}
				}
				else
				{
					runCmdA(appname, buff, command_line, indexABCD);
				}
 			}
		}	// the code above looks good
		else
		{	// position B is null
			if(positionC!=NULL)
			{
				for(k=0;k<203;k++)
				{
					buff[indexABCD[2]] = fuzz_bytes[k];
					if(positionD!=NULL)
					{
						for(l=0;l<203;l++)
						{
							buff[indexABCD[3]] = fuzz_bytes[l];
							runCmdA(appname, buff, command_line, indexABCD);	
						}
					}
					else
					{	// position D is NULL, we're done here
						runCmdA(appname, buff, command_line, indexABCD);
					}
				}
 			}
			else
			{
				if(positionD!=NULL)
				{
					for(l=0;l<203;l++)
					{
						buff[indexABCD[3]] = fuzz_bytes[l];
						runCmdA(appname, buff, command_line, indexABCD);	
					}
				}
				else
				{	// position D is NULL, we're done here
					runCmdA(appname, buff, command_line, indexABCD);
				}
			}
		} // the code above looks good	
	}
}

int main(int argc, char** argv) 
{
	unsigned int count = sizeof(templates)/8; // sizeof divided by 8 - count
	if(argc!=2)
	{
		printf("Usage: %s <NUM>\nWhereas <NUM> is a number.", argv[0]);
		return;
	}
	int index = atoi(argv[1]);
	if(index>=count)
	{
		printf("Number must be between 0 and %u.\n", count);
		return;
	}

	char outname[20];
	memset(outname,0,20);
	snprintf(outname,20,"OUTPUT-%u.txt",index);
	outfile = CreateFile(outname,                // name of the write
                       GENERIC_WRITE|GENERIC_READ,    // open for reading & writing
                       FILE_SHARE_READ,               
                       NULL,                   // default security
                       CREATE_ALWAYS,          // create new file only
                       FILE_ATTRIBUTE_NORMAL,  // normal file
                       NULL);                  // no attr. template
	if (outfile == INVALID_HANDLE_VALUE) 
	{ 
		printf("FATAL ERROR: Could not open the OUTPUT.txt for writing, exiting.");
		return -1;
	}
	// templates generated with cmd-fuzzing-generate-templates.py
	fuzzABCD(templates[index]);
	CloseHandle(outfile);
	return 0;	
}
