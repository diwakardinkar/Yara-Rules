# Yara-Rules
# Yara rule to detect GPGQuerty ransomware !
rule GPGQwerty : GPGQwerty
{
	strings:
	
		$a = "gpg.exe --recipient qwerty  -o"
		$b = "%s%s.%d.qwerty"
        $c = "del /Q /F /S %s$recycle.bin"
        $d = "cryz1@protonmail.com"
        
    condition:
		all of them
}
