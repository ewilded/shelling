## payload_generator
## Trying to define and implement a proper anatomy of nix command injection
## Let's try to create proper nix command injection anatomy
## we can deal with three types of shitty check filters:
## 1) the ones that only force the string to begin properly, like ^\w+ 
## 2) the ones that only force the string to end properly, like \w+$
## 3) the ones that only force the string to have proper beginning and end, with a loophole inside of them, e.g. ^\w+\s+.*\w+$
## We have to create the base payloads list with this thing in mind
## This is why we need both SUFFIXES and PREFIXES, we build all combinations: 
## PREFIX{PAYLOAD}, PREFIX{PAYLOAD}SUFFIX, {PAYLOAD}SUFFIX,
## we'll also be able to cover injection points starting/ending with quotes

## MALICIOUS_COMMAND=COMMAND+ARGUMENT_SEPARATOR
## THE COMBINATION PATTERNS: 
## 1) MALICIOUS_COMMAND (will this ever happen? yes it will, in argument injections like `$USER_SUPPLIED` or $(USER_SUPPLIED))
## 2) MALICIOUS_COMMAND+COMMAND_TERMINATOR (in case there was write and command separators were unallowed?)
## 3) COMMAND_SEPARATOR+MALICIOUS_COMMAND (for simple injections with no filtering, like cat $USER_SUPPLIED
## 4) COMMAND_SEPARATOR+MALICIOUS_COMMAND+COMMAND_SEPARATOR (for simple injections with no filtering and appended fixed shite, like cat $USER_SUPPLIED something)
## 5) COMMAND_SEPARATOR+MALICIOUS_COMMAND+COMMAND_SEPARATOR+SUFFIX (for simple injections like cat $USER_SUPPLIED something, with filtering like \w+$)
## 6) PREFIX+COMMAND_SEPARATOR+MALICIOUS_COMMAND+COMMAND_SEPARATOR (for injections with shitty filtering like ^\w+ and some appended fixed shite, like cat $USER_SUPPLIED something)
## 7) PREFIX+COMMAND_SEPARATOR+MALICIOUS_COMMAND+COMMAND_SEPARATOR+SUFFIX (for injections with appended fixed shite, like cat $USER_SUPPLIED something, with shitty filtering like ^\w+\s+.*\w+$)

## Why we do not combine COMMAND_SEPARATORS along with COMMAND_TERMINATORS in one payload: any quotes will be handled by the prefix stuff anyway, while any fixed appendices will be ignored due to separators instead of terminators (and if separator is not accepted, the command will fail anyway, so there is no point in trailing it with a terminator)... hence, terminators should be used only mutually exclusively with separators!
