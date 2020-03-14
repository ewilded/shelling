// The goal of this is to dynamically test how cmd.exe handles input from functions like CreateProcessA()/Shellexec, to highlight any potential vectors for a universal command injection vulnerability.
// This general meta-PoC application explores all the attack vectors desribed in ATTACK_VECTORS.txt.

// COMBINATORICS:
// we should retest the following combinations:
// with both space and without space after whoami * ALL quote syntaxes INCLUDING quote mixing * all /c /K and other switches (maybe where are some hidden as well) * multiple characters 

// Multiple characters involves:
// - wide ascii/UTF
// - double characters (as per the documentation, && works as a command separator in quoted strings, maybe there's something else that does?)

// Successfully compiled & run with Dev CPP on Win10 x64.
// "C:\Program Files (x86)\Dev-Cpp\MinGW64\bin\gcc.exe" "C:\Users\ewilded\HACKING\SHELLING\research\cmd.exe\fuzzing\fuzzing.c" -o "C:\Users\ewilded\HACKING\SHELLING\research\cmd.exe\fuzzing\fuzzing.exe"  -I"C:\Program Files (x86)\Dev-Cpp\MinGW64\include" -I"C:\Program Files (x86)\Dev-Cpp\MinGW64\x86_64-w64-mingw32\include" -I"C:\Program Files (x86)\Dev-Cpp\MinGW64\lib\gcc\x86_64-w64-mingw32\4.9.2\include" -I"C:\Users\ewilded\TOOLS\openssl\openssl-0.9.8h-1-lib\include" -L"C:\Program Files (x86)\Dev-Cpp\MinGW64\lib" -L"C:\Program Files (x86)\Dev-Cpp\MinGW64\x86_64-w64-mingw32\lib" -static-libgcc

//
#include <windows.h>
#include <string.h>
#include <stdio.h>

// this is the range for single-byte fuzzing - alnum are skipped to reduce the junk results, thus a fixed array instead of just range in an array

byte fuzz_bytes[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 91, 92, 93, 94, 95, 96, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254}; // up to 255

void runCmdA(LPSTR appname, char * command_line, const char * command_template, int * indexbytes)
{
	// printf("[DEBUG] Trying %s \n",command_template); // actually this can be printed earlier
	int slen = strlen(command_template);
	int i;
	printf(" ");
	for(i=0;i<slen;i++)
	{
		if(command_template[i]=='A')
		{
			printf("[%u]",(byte)command_line[indexbytes[0]]);
		}
		if(command_template[i]=='B')
		{
			printf("[%u]",(byte)command_line[indexbytes[1]]);
		}
		if(command_template[i]=='C')
		{
			printf("[%u]",(byte)command_line[indexbytes[2]]);
		}
		if(command_template[i]=='D')
		{
			printf("[%u]",(byte)command_line[indexbytes[3]]);
		}
	}
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
	int proc = CreateProcessA(appname, (LPSTR)command_line, 0, 0, TRUE, NORMAL_PRIORITY_CLASS, NULL, NULL, si_w, &pi);
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
		if(strstr(outbuf,"desktop"))
		{
			printf("[+]"); // just indicates that the first command executed, helpful for studying different syntax approaches
		}
		if(strstr(outbuf,"EXECUTION"))
		{
			printf("[SUCCESS!]: %s\n",command_line);
			//printf("\n%s\n",outbuf);
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
		printf("\n");
		return;
	}
}
// this function takes one param: the command_line template string (the general syntax), locates the index of the "A" letter and does fuzzing by automatically replacing it with payloads
void fuzzABCD(char * command_line) 
{
	//printf("CHUJ");
	LPSTR appname ="C:\\Windows\\system32\\cmd.exe";
	char buff[100];
	memset(buff,0,100);
	strcpy(buff,command_line); // wink wink ;]
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
	
	printf(command_line);

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
		} // the code above looks good	
	}
}

int main(int argc, char** argv) 
{
	// 1. read the templates in
	// 2. fuzz
	// 3. grep the output
	/*
	char command_template[100];
	memset(command_template,0,100);	
	scanf("%s" , command_template); // wink wink, buffer overflow ;]
	printf("%s", command_template);
	*/
	char * templates[] = {"/c \"whoami <A><B>rnme\"", "/c \"whoami <A><B>rnme'", "/c \"whoami<A><B>rnme\"", "/c \"whoami<A><B>rnme'", "/c 'whoami <A><B>rnme\"", "/c 'whoami <A><B>rnme'", "/c 'whoami<A><B>rnme\"", "/c 'whoami<A><B>rnme'", "/c whoami <A><B>rnme\"", "/c whoami <A><B>rnme'", "/c whoami<A><B>rnme\"", "/c whoami<A><B>rnme'", "/c \"whoami <A><B>rnme<C>", "/c \"whoami<A><B>rnme<C>", "/c 'whoami <A><B>rnme<C>", "/c 'whoami<A><B>rnme<C>", "/c whoami <A><B>rnme<C>", "/c whoami<A><B>rnme<C>", "/c \"whoami <A><B>rnme<C><D>", "/c \"whoami<A><B>rnme<C><D>", "/c 'whoami <A><B>rnme<C><D>", "/c 'whoami<A><B>rnme<C><D>", "/c whoami <A><B>rnme<C><D>", "/c whoami<A><B>rnme<C><D>", "/c \"whoami <A><B>rnme\"<D>", "/c \"whoami <A><B>rnme'<D>", "/c \"whoami<A><B>rnme\"<D>", "/c \"whoami<A><B>rnme'<D>", "/c 'whoami <A><B>rnme\"<D>", "/c 'whoami <A><B>rnme'<D>", "/c 'whoami<A><B>rnme\"<D>", "/c 'whoami<A><B>rnme'<D>", "/c whoami <A><B>rnme\"<D>", "/c whoami <A><B>rnme'<D>", "/c whoami<A><B>rnme\"<D>", "/c whoami<A><B>rnme'<D>", "/c \"whoami <A>rnme\"", "/c \"whoami <A>rnme'", "/c \"whoami<A>rnme\"", "/c \"whoami<A>rnme'", "/c 'whoami <A>rnme\"", "/c 'whoami <A>rnme'", "/c 'whoami<A>rnme\"", "/c 'whoami<A>rnme'", "/c whoami <A>rnme\"", "/c whoami <A>rnme'", "/c whoami<A>rnme\"", "/c whoami<A>rnme'", "/c \"whoami <A>rnme<C>", "/c \"whoami<A>rnme<C>", "/c 'whoami <A>rnme<C>", "/c 'whoami<A>rnme<C>", "/c whoami <A>rnme<C>", "/c whoami<A>rnme<C>", "/c \"whoami <A>rnme<C><D>", "/c \"whoami<A>rnme<C><D>", "/c 'whoami <A>rnme<C><D>", "/c 'whoami<A>rnme<C><D>", "/c whoami <A>rnme<C><D>", "/c whoami<A>rnme<C><D>", "/c \"whoami <A>rnme\"<D>", "/c \"whoami <A>rnme'<D>", "/c \"whoami<A>rnme\"<D>", "/c \"whoami<A>rnme'<D>", "/c 'whoami <A>rnme\"<D>", "/c 'whoami <A>rnme'<D>", "/c 'whoami<A>rnme\"<D>", "/c 'whoami<A>rnme'<D>", "/c whoami <A>rnme\"<D>", "/c whoami <A>rnme'<D>", "/c whoami<A>rnme\"<D>", "/c whoami<A>rnme'<D>", "/c \"whoami \"<B>rnme\"", "/c \"whoami \"<B>rnme'", "/c \"whoami '<B>rnme\"", "/c \"whoami '<B>rnme'", "/c \"whoami\"<B>rnme\"", "/c \"whoami\"<B>rnme'", "/c \"whoami'<B>rnme\"", "/c \"whoami'<B>rnme'", "/c 'whoami \"<B>rnme\"", "/c 'whoami \"<B>rnme'", "/c 'whoami '<B>rnme\"", "/c 'whoami '<B>rnme'", "/c 'whoami\"<B>rnme\"", "/c 'whoami\"<B>rnme'", "/c 'whoami'<B>rnme\"", "/c 'whoami'<B>rnme'", "/c whoami \"<B>rnme\"", "/c whoami \"<B>rnme'", "/c whoami '<B>rnme\"", "/c whoami '<B>rnme'", "/c whoami\"<B>rnme\"", "/c whoami\"<B>rnme'", "/c whoami'<B>rnme\"", "/c whoami'<B>rnme'", "/c \"whoami \"<B>rnme<C>", "/c \"whoami '<B>rnme<C>", "/c \"whoami\"<B>rnme<C>", "/c \"whoami'<B>rnme<C>", "/c 'whoami \"<B>rnme<C>", "/c 'whoami '<B>rnme<C>", "/c 'whoami\"<B>rnme<C>", "/c 'whoami'<B>rnme<C>", "/c whoami \"<B>rnme<C>", "/c whoami '<B>rnme<C>", "/c whoami\"<B>rnme<C>", "/c whoami'<B>rnme<C>", "/c \"whoami \"<B>rnme<C><D>", "/c \"whoami '<B>rnme<C><D>", "/c \"whoami\"<B>rnme<C><D>", "/c \"whoami'<B>rnme<C><D>", "/c 'whoami \"<B>rnme<C><D>", "/c 'whoami '<B>rnme<C><D>", "/c 'whoami\"<B>rnme<C><D>", "/c 'whoami'<B>rnme<C><D>", "/c whoami \"<B>rnme<C><D>", "/c whoami '<B>rnme<C><D>", "/c whoami\"<B>rnme<C><D>", "/c whoami'<B>rnme<C><D>", "/c \"whoami \"<B>rnme\"<D>", "/c \"whoami \"<B>rnme'<D>", "/c \"whoami '<B>rnme\"<D>", "/c \"whoami '<B>rnme'<D>", "/c \"whoami\"<B>rnme\"<D>", "/c \"whoami\"<B>rnme'<D>", "/c \"whoami'<B>rnme\"<D>", "/c \"whoami'<B>rnme'<D>", "/c 'whoami \"<B>rnme\"<D>", "/c 'whoami \"<B>rnme'<D>", "/c 'whoami '<B>rnme\"<D>", "/c 'whoami '<B>rnme'<D>", "/c 'whoami\"<B>rnme\"<D>", "/c 'whoami\"<B>rnme'<D>", "/c 'whoami'<B>rnme\"<D>", "/c 'whoami'<B>rnme'<D>", "/c whoami \"<B>rnme\"<D>", "/c whoami \"<B>rnme'<D>", "/c whoami '<B>rnme\"<D>", "/c whoami '<B>rnme'<D>", "/c whoami\"<B>rnme\"<D>", "/c whoami\"<B>rnme'<D>", "/c whoami'<B>rnme\"<D>", "/c whoami'<B>rnme'<D>", "/c \"whoami \"rnme\"", "/c \"whoami \"rnme'", "/c \"whoami 'rnme\"", "/c \"whoami 'rnme'", "/c \"whoami\"rnme\"", "/c \"whoami\"rnme'", "/c \"whoami'rnme\"", "/c \"whoami'rnme'", "/c 'whoami \"rnme\"", "/c 'whoami \"rnme'", "/c 'whoami 'rnme\"", "/c 'whoami 'rnme'", "/c 'whoami\"rnme\"", "/c 'whoami\"rnme'", "/c 'whoami'rnme\"", "/c 'whoami'rnme'", "/c whoami \"rnme\"", "/c whoami \"rnme'", "/c whoami 'rnme\"", "/c whoami 'rnme'", "/c whoami\"rnme\"", "/c whoami\"rnme'", "/c whoami'rnme\"", "/c whoami'rnme'", "/c \"whoami \"rnme<C>", "/c \"whoami 'rnme<C>", "/c \"whoami\"rnme<C>", "/c \"whoami'rnme<C>", "/c 'whoami \"rnme<C>", "/c 'whoami 'rnme<C>", "/c 'whoami\"rnme<C>", "/c 'whoami'rnme<C>", "/c whoami \"rnme<C>", "/c whoami 'rnme<C>", "/c whoami\"rnme<C>", "/c whoami'rnme<C>", "/c \"whoami \"rnme<C><D>", "/c \"whoami 'rnme<C><D>", "/c \"whoami\"rnme<C><D>", "/c \"whoami'rnme<C><D>", "/c 'whoami \"rnme<C><D>", "/c 'whoami 'rnme<C><D>", "/c 'whoami\"rnme<C><D>", "/c 'whoami'rnme<C><D>", "/c whoami \"rnme<C><D>", "/c whoami 'rnme<C><D>", "/c whoami\"rnme<C><D>", "/c whoami'rnme<C><D>", "/c \"whoami \"rnme\"<D>", "/c \"whoami \"rnme'<D>", "/c \"whoami 'rnme\"<D>", "/c \"whoami 'rnme'<D>", "/c \"whoami\"rnme\"<D>", "/c \"whoami\"rnme'<D>", "/c \"whoami'rnme\"<D>", "/c \"whoami'rnme'<D>", "/c 'whoami \"rnme\"<D>", "/c 'whoami \"rnme'<D>", "/c 'whoami 'rnme\"<D>", "/c 'whoami 'rnme'<D>", "/c 'whoami\"rnme\"<D>", "/c 'whoami\"rnme'<D>", "/c 'whoami'rnme\"<D>", "/c 'whoami'rnme'<D>", "/c whoami \"rnme\"<D>", "/c whoami \"rnme'<D>", "/c whoami 'rnme\"<D>", "/c whoami 'rnme'<D>", "/c whoami\"rnme\"<D>", "/c whoami\"rnme'<D>", "/c whoami'rnme\"<D>", "/c whoami'rnme'<D>", "/r \"whoami <A><B>rnme\"", "/r \"whoami <A><B>rnme'", "/r \"whoami<A><B>rnme\"", "/r \"whoami<A><B>rnme'", "/r 'whoami <A><B>rnme\"", "/r 'whoami <A><B>rnme'", "/r 'whoami<A><B>rnme\"", "/r 'whoami<A><B>rnme'", "/r whoami <A><B>rnme\"", "/r whoami <A><B>rnme'", "/r whoami<A><B>rnme\"", "/r whoami<A><B>rnme'", "/r \"whoami <A><B>rnme<C>", "/r \"whoami<A><B>rnme<C>", "/r 'whoami <A><B>rnme<C>", "/r 'whoami<A><B>rnme<C>", "/r whoami <A><B>rnme<C>", "/r whoami<A><B>rnme<C>", "/r \"whoami <A><B>rnme<C><D>", "/r \"whoami<A><B>rnme<C><D>", "/r 'whoami <A><B>rnme<C><D>", "/r 'whoami<A><B>rnme<C><D>", "/r whoami <A><B>rnme<C><D>", "/r whoami<A><B>rnme<C><D>", "/r \"whoami <A><B>rnme\"<D>", "/r \"whoami <A><B>rnme'<D>", "/r \"whoami<A><B>rnme\"<D>", "/r \"whoami<A><B>rnme'<D>", "/r 'whoami <A><B>rnme\"<D>", "/r 'whoami <A><B>rnme'<D>", "/r 'whoami<A><B>rnme\"<D>", "/r 'whoami<A><B>rnme'<D>", "/r whoami <A><B>rnme\"<D>", "/r whoami <A><B>rnme'<D>", "/r whoami<A><B>rnme\"<D>", "/r whoami<A><B>rnme'<D>", "/r \"whoami <A>rnme\"", "/r \"whoami <A>rnme'", "/r \"whoami<A>rnme\"", "/r \"whoami<A>rnme'", "/r 'whoami <A>rnme\"", "/r 'whoami <A>rnme'", "/r 'whoami<A>rnme\"", "/r 'whoami<A>rnme'", "/r whoami <A>rnme\"", "/r whoami <A>rnme'", "/r whoami<A>rnme\"", "/r whoami<A>rnme'", "/r \"whoami <A>rnme<C>", "/r \"whoami<A>rnme<C>", "/r 'whoami <A>rnme<C>", "/r 'whoami<A>rnme<C>", "/r whoami <A>rnme<C>", "/r whoami<A>rnme<C>", "/r \"whoami <A>rnme<C><D>", "/r \"whoami<A>rnme<C><D>", "/r 'whoami <A>rnme<C><D>", "/r 'whoami<A>rnme<C><D>", "/r whoami <A>rnme<C><D>", "/r whoami<A>rnme<C><D>", "/r \"whoami <A>rnme\"<D>", "/r \"whoami <A>rnme'<D>", "/r \"whoami<A>rnme\"<D>", "/r \"whoami<A>rnme'<D>", "/r 'whoami <A>rnme\"<D>", "/r 'whoami <A>rnme'<D>", "/r 'whoami<A>rnme\"<D>", "/r 'whoami<A>rnme'<D>", "/r whoami <A>rnme\"<D>", "/r whoami <A>rnme'<D>", "/r whoami<A>rnme\"<D>", "/r whoami<A>rnme'<D>", "/r \"whoami \"<B>rnme\"", "/r \"whoami \"<B>rnme'", "/r \"whoami '<B>rnme\"", "/r \"whoami '<B>rnme'", "/r \"whoami\"<B>rnme\"", "/r \"whoami\"<B>rnme'", "/r \"whoami'<B>rnme\"", "/r \"whoami'<B>rnme'", "/r 'whoami \"<B>rnme\"", "/r 'whoami \"<B>rnme'", "/r 'whoami '<B>rnme\"", "/r 'whoami '<B>rnme'", "/r 'whoami\"<B>rnme\"", "/r 'whoami\"<B>rnme'", "/r 'whoami'<B>rnme\"", "/r 'whoami'<B>rnme'", "/r whoami \"<B>rnme\"", "/r whoami \"<B>rnme'", "/r whoami '<B>rnme\"", "/r whoami '<B>rnme'", "/r whoami\"<B>rnme\"", "/r whoami\"<B>rnme'", "/r whoami'<B>rnme\"", "/r whoami'<B>rnme'", "/r \"whoami \"<B>rnme<C>", "/r \"whoami '<B>rnme<C>", "/r \"whoami\"<B>rnme<C>", "/r \"whoami'<B>rnme<C>", "/r 'whoami \"<B>rnme<C>", "/r 'whoami '<B>rnme<C>", "/r 'whoami\"<B>rnme<C>", "/r 'whoami'<B>rnme<C>", "/r whoami \"<B>rnme<C>", "/r whoami '<B>rnme<C>", "/r whoami\"<B>rnme<C>", "/r whoami'<B>rnme<C>", "/r \"whoami \"<B>rnme<C><D>", "/r \"whoami '<B>rnme<C><D>", "/r \"whoami\"<B>rnme<C><D>", "/r \"whoami'<B>rnme<C><D>", "/r 'whoami \"<B>rnme<C><D>", "/r 'whoami '<B>rnme<C><D>", "/r 'whoami\"<B>rnme<C><D>", "/r 'whoami'<B>rnme<C><D>", "/r whoami \"<B>rnme<C><D>", "/r whoami '<B>rnme<C><D>", "/r whoami\"<B>rnme<C><D>", "/r whoami'<B>rnme<C><D>", "/r \"whoami \"<B>rnme\"<D>", "/r \"whoami \"<B>rnme'<D>", "/r \"whoami '<B>rnme\"<D>", "/r \"whoami '<B>rnme'<D>", "/r \"whoami\"<B>rnme\"<D>", "/r \"whoami\"<B>rnme'<D>", "/r \"whoami'<B>rnme\"<D>", "/r \"whoami'<B>rnme'<D>", "/r 'whoami \"<B>rnme\"<D>", "/r 'whoami \"<B>rnme'<D>", "/r 'whoami '<B>rnme\"<D>", "/r 'whoami '<B>rnme'<D>", "/r 'whoami\"<B>rnme\"<D>", "/r 'whoami\"<B>rnme'<D>", "/r 'whoami'<B>rnme\"<D>", "/r 'whoami'<B>rnme'<D>", "/r whoami \"<B>rnme\"<D>", "/r whoami \"<B>rnme'<D>", "/r whoami '<B>rnme\"<D>", "/r whoami '<B>rnme'<D>", "/r whoami\"<B>rnme\"<D>", "/r whoami\"<B>rnme'<D>", "/r whoami'<B>rnme\"<D>", "/r whoami'<B>rnme'<D>", "/r \"whoami \"rnme\"", "/r \"whoami \"rnme'", "/r \"whoami 'rnme\"", "/r \"whoami 'rnme'", "/r \"whoami\"rnme\"", "/r \"whoami\"rnme'", "/r \"whoami'rnme\"", "/r \"whoami'rnme'", "/r 'whoami \"rnme\"", "/r 'whoami \"rnme'", "/r 'whoami 'rnme\"", "/r 'whoami 'rnme'", "/r 'whoami\"rnme\"", "/r 'whoami\"rnme'", "/r 'whoami'rnme\"", "/r 'whoami'rnme'", "/r whoami \"rnme\"", "/r whoami \"rnme'", "/r whoami 'rnme\"", "/r whoami 'rnme'", "/r whoami\"rnme\"", "/r whoami\"rnme'", "/r whoami'rnme\"", "/r whoami'rnme'", "/r \"whoami \"rnme<C>", "/r \"whoami 'rnme<C>", "/r \"whoami\"rnme<C>", "/r \"whoami'rnme<C>", "/r 'whoami \"rnme<C>", "/r 'whoami 'rnme<C>", "/r 'whoami\"rnme<C>", "/r 'whoami'rnme<C>", "/r whoami \"rnme<C>", "/r whoami 'rnme<C>", "/r whoami\"rnme<C>", "/r whoami'rnme<C>", "/r \"whoami \"rnme<C><D>", "/r \"whoami 'rnme<C><D>", "/r \"whoami\"rnme<C><D>", "/r \"whoami'rnme<C><D>", "/r 'whoami \"rnme<C><D>", "/r 'whoami 'rnme<C><D>", "/r 'whoami\"rnme<C><D>", "/r 'whoami'rnme<C><D>", "/r whoami \"rnme<C><D>", "/r whoami 'rnme<C><D>", "/r whoami\"rnme<C><D>", "/r whoami'rnme<C><D>", "/r \"whoami \"rnme\"<D>", "/r \"whoami \"rnme'<D>", "/r \"whoami 'rnme\"<D>", "/r \"whoami 'rnme'<D>", "/r \"whoami\"rnme\"<D>", "/r \"whoami\"rnme'<D>", "/r \"whoami'rnme\"<D>", "/r \"whoami'rnme'<D>", "/r 'whoami \"rnme\"<D>", "/r 'whoami \"rnme'<D>", "/r 'whoami 'rnme\"<D>", "/r 'whoami 'rnme'<D>", "/r 'whoami\"rnme\"<D>", "/r 'whoami\"rnme'<D>", "/r 'whoami'rnme\"<D>", "/r 'whoami'rnme'<D>", "/r whoami \"rnme\"<D>", "/r whoami \"rnme'<D>", "/r whoami 'rnme\"<D>", "/r whoami 'rnme'<D>", "/r whoami\"rnme\"<D>", "/r whoami\"rnme'<D>", "/r whoami'rnme\"<D>", "/r whoami'rnme'<D>"};
	int count = sizeof(templates)/8; // sizeof divided by 8 - count
	printf("%d ",count); 
	int i=0;
	for(i=0;i<count;i++) fuzzABCD(templates[i]);
	return 0;	
}
