# SHELLING - an offensive approach to the anatomy of improperly written OS command injection sanitisers

In order to improve the accuracy of our blind OS command injection testing, we need a comprehensive, analytic approach. In general, our injection payloads may fail to provide us with positive feedback due to:
- the eventual syntax of the expression we are injecting into (solution: base payload variants)
- input sanitising mechanisms, which refuse forbidden characters (solution: evasive techniques)
- platform specific conditions (e.g. using a windows command on a nix host)
- bad callback method (e.g. asynchronous execution, no outbound traffic etc., solution: base payload variants)

The goal of this tool is to create a comprehensive set of test cases providing solutions to all possible combinations of these issues at a time.

BASE PAYLOAD VARIANTS (BASIC CASES)

- MALICIOUS_COMMAND (will this ever happen? yes it will, in argument injections like `$USER_SUPPLIED` or $(USER_SUPPLIED))
- MALICIOUS_COMMAND+COMMAND_TERMINATOR (in case there was write and command separators were unallowed?)
- COMMAND_SEPARATOR+MALICIOUS_COMMAND (for simple injections with no filtering, like cat $USER_SUPPLIED
- COMMAND_SEPARATOR+MALICIOUS_COMMAND+COMMAND_SEPARATOR (for simple injections with no filtering and appended fixed shite, like cat $USER_SUPPLIED something)
- COMMAND_SEPARATOR+MALICIOUS_COMMAND+COMMAND_SEPARATOR+SUFFIX (for simple injections like cat $USER_SUPPLIED something, with filtering like \w+$)
- PREFIX+COMMAND_SEPARATOR+MALICIOUS_COMMAND+COMMAND_SEPARATOR (for injections with shitty filtering like ^\w+ and some appended fixed shite, like cat $USER_SUPPLIED something)
- PREFIX+COMMAND_SEPARATOR+MALICIOUS_COMMAND+COMMAND_SEPARATOR+SUFFIX (for injections with appended fixed shite, like cat $USER_SUPPLIED something, with shitty filtering like ^\w+\s+.*\w+$)
- PREFIX+MALICIOUS_COMMAND+SUFFIX (`` and $() notations)



EVASIVE TECHNIQUES USED
- alternative COMMAND_SEPARATORS
- alternative ARGUMENT_SEPARATORS
- alternative COMMAND_TERMINATORS
- additional prefixes and suffixes to go around lax filters
- additional prefixes and suffixes to fit into quoted expressions

Other evasive techniques considered:
- alternative payloads to avoid particular badcharacters
- encoding-related variations, like double URL encoding

A more comprehensive version of this README: https://github.com/ewilded/shelling/blob/master/README.pdf
