#!/bin/bash
#Opens new terminal for script

echo -e "\033[38;2;12;36;251m██▓███   █    ██  \033[38;2;13;46;250m██▓      \033[38;2;14;55;249m█████ \033[38;2;15;65;248m▓██████▄"
echo -e "\033[38;2;16;74;247m▓██░  ██▒ ██  ▓██▒▓██▒    \033[38;2;17;84;246m▒██    ▒  ▓█░  "
echo -e "\033[38;2;17;93;245m▓██░ ██▓▒▓██  ▒██░▒██░    ░ \033[38;2;18;105;244m▓██▄   ▒███▀"
echo -e "\033[38;2;19;112;243m▒██▄█▓▒ ▒▓▓█  ░██░▒██░      ▒   ██▒▒▓█  ██ "
echo -e "\033[38;2;19;122;242m▒██▒ ▒  ░▒▒█████▓ ░██████▒▒██████▒▒░▒████▒"
echo -e "\033[38;2;22;128;240m▒▓▒░ ░  ░░▒▓▒ ▒ ▒ ░ ▒░▓  ░▒ ▒▓▒ ▒ ░░░ ░ ░░"
echo -e "\033[38;2;23;160;239m░▒ ░     ░░▒░ ░ ░ ░ ░ ▒ ░ ░    ░ ░   ░  ░"
echo -e "\033[38;2;24;169;238m ░    ░   ░░░ ░ ░   ░ ░   ░  ░  ░     ░"
echo -e "\033[38;2;25;176;237m   ░  ░     ░         ░    ░         ░  ░"

fullScript() {
Report=""

#fixes a lot of permission for files
sudo chmod 640 /etc/shadow
sudo chmod 644 /etc/passwd
sudo chmod 600 /boot/grub/grub.cfg
sudo chmod 644 /etc/group
sudo chmod 640 /etc/gshadow
sudo chmod 440 /etc/sudoers
sudo chmod 644 /etc/hostname
sudo chmod 644 /etc/resolv.conf
sudo chmod 644 /etc/hosts
sudo chmod 644 /etc/issue
sudo chmod 644 /etc/motd
sudo chmod 600 /etc/ssh/sshd_config
sudo chmod 644 /etc/selinux/config
sudo chmod 755 /etc
sudo chmod 755 /sbin
sudo chmod 755 /lib
sudo chmod 755 /var
sudo chmod 755 /bin
sudo chmod 755 /boot
sudo chmod 755 /opt
sudo chmod 755 /dev
sudo chmod 755 /srv
sudo chmod 755 /media
sudo chmod 755 /mnt
sudo chmod 755 /usr
sudo chmod 640 /var/log/auth.log
sudo chmod 640 /var/log/syslog
sudo chmod 640 /var/log/kern.log
sudo chmod 640 /var/log/daemon.log
sudo chmod 640 /var/log/messages
sudo chmod o-w /tmp
sudo chmod o-w /var/tmp
sudo chmod +t /tmp
sudo chmod +t /var/tmp
sudo chmod 755 /bin
sudo chmod 755 /sbin
sudo chmod 755 /usr/bin
sudo chmod 755 /usr/sbin
sudo chmod 700 /usr/bin/ssh
sudo chmod 700 /usr/bin/sudo
sudo chmod 600 /boot/vmlinuz-*
sudo chmod 600 /boot/initrd.img-*

#Enable ufw
sudo apt install ufw -y
sudo ufw enable
sudo ufw allow ssh
sudo ufw allow 80
sudo ufw default deny incoming
sudo ufw default allow outgoing

#Remove unnecessary files
sudo apt autoremove --purge -y

#Enable apache2
sudo apt install apache2 -y
sudo systemctl enable apache2
sudo systemctl start apache2

#Enable apparmor
sudo apt install apparmor apparmor-utils -y
sudo systemctl enable apparmor
sudo systemctl start apparmor

#Fix configuration in /etc/sysctl.conf
sudo sed -i '/^net\.ipv6\.conf\.all\.disable_ipv6/d' /etc/sysctl.conf
sudo sed -i '/^net\.ipv6\.conf\.default\.disable_ipv6/d' /etc/sysctl.conf
echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -w net.ipv4.ip_forward=0
sudo sysctl -p

#Fix configuration in /etc/login.defs
LOGIN_DEFS="/etc/login.defs"
sudo cp "$LOGIN_DEFS" "${LOGIN_DEFS}.bak"
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' "$LOGIN_DEFS"
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' "$LOGIN_DEFS"
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' "$LOGIN_DEFS"
sudo sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' "$LOGIN_DEFS"

#Remove root imposters
awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd | while read user; do
    sed -i "/^$user:/d" /etc/passwd
    sed -i "/^$user:/d" /etc/shadow
done

#Fixes /etc/shells
valid_lines=(
  "# /etc/shells: valid login shells"
  "/bin/sh"
  "/bin/bash"
  "/usr/bin/bash"
  "/bin/rbash"
  "/usr/bin/rbash"
  "/usr/bin/sh"
  "/bin/dash"
  "/usr/bin/dash"
)
current_lines=$(cat /etc/shells)
while read -r line; do
  line=$(echo "$line" | sed 's/^[ \t]*//;s/[ \t]*$//')
  if [[ -n $line && ! " ${valid_lines[*]} " =~ " $line " ]]; then
    Report+="$line"$'\n'
  fi
done <<< "$current_lines"
Report=$(echo -e "$Report" | sed '/^$/d')
if [[ -n $Report ]]; then
  echo "Lines not in the predefined set:"
  echo "$Report"
fi
sudo sed -i '/\/sbin\/nologin/d; /\/bin\/false/d' /etc/shells

#Fix System-User shells
awk -F: '($3 < 1000 && $7 != "/usr/sbin/nologin" && $7 != "/bin/false") {print $1}' /etc/passwd | while read user; do
    sudo usermod -s /usr/sbin/nologin "$user"
done

#Fixes configuration in /etc/security/pwquality.conf
PWQUALITY_CONFIG="/etc/security/pwquality.conf"
sudo cp "$PWQUALITY_CONFIG" "${PWQUALITY_CONFIG}.bak"
sudo sed -i '/^minlen/d' "$PWQUALITY_CONFIG"
sudo sed -i '/^minclass/d' "$PWQUALITY_CONFIG"
sudo sed -i '/^maxrepeat/d' "$PWQUALITY_CONFIG"
sudo sed -i '/^dcredit/d' "$PWQUALITY_CONFIG"
sudo sed -i '/^ucredit/d' "$PWQUALITY_CONFIG"
sudo sed -i '/^ocredit/d' "$PWQUALITY_CONFIG"
sudo sed -i '/^lcredit/d' "$PWQUALITY_CONFIG"
cat <<EOL | sudo tee -a "$PWQUALITY_CONFIG"
minlen = 12
minclass = 4
maxrepeat = 2
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
EOL

#Fixes Grub
sudo grub-mkpasswd-pbkdf2
GRUB_CONFIG="/etc/default/grub"
sudo cp "$GRUB_CONFIG" "${GRUB_CONFIG}.bak"
sudo sed -i 's|^GRUB_CMDLINE_LINUX=".*"|GRUB_CMDLINE_LINUX="security=apparmor"|g' "$GRUB_CONFIG"
sudo sed -i 's|^GRUB_CMDLINE_LINUX_DEFAULT=".*"|GRUB_CMDLINE_LINUX_DEFAULT="quiet splash kaslr"|g' "$GRUB_CONFIG"
sudo update-grub

#Fixes sshd config
SSH_CONFIG="/etc/ssh/sshd_config"
sudo cp "$SSH_CONFIG" "${SSH_CONFIG}.bak"
sudo sed -i '/^PermitRootLogin/d' "$SSH_CONFIG"
sudo sed -i '/^MaxAuthTries/d' "$SSH_CONFIG"
sudo sed -i '/^PasswordAuthentication/d' "$SSH_CONFIG"
echo "PermitRootLogin no" | sudo tee -a "$SSH_CONFIG"
echo "MaxAuthTries 3" | sudo tee -a "$SSH_CONFIG"
echo "PasswordAuthentication yes" | sudo tee -a "$SSH_CONFIG"
sudo systemctl restart ssh

#Fixes configuration in /etc/audit/rules.d/audit.rules
AUDIT_RULES_FILE="/etc/audit/rules.d/audit.rules"
sudo cp "$AUDIT_RULES_FILE" "${AUDIT_RULES_FILE}.bak"
cat <<EOL | sudo tee -a "$AUDIT_RULES_FILE"
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /var/log/secure -p wa -k auth_logs
-w /usr/bin/sudo -p x -k sudo_usage
-w /etc/ssh/sshd_config -p wa -k ssh_changes
EOL
sudo systemctl restart auditd

echo -e "\033[1;32m\033[5mFINISHED SCRIPT!\033[0m"
echo -e " "
}

fillUserPasswords() {
#Add passwords to users without passwords (VARIABLES)
PASSWORD="Password123!"
editAdminPasswords=true
editNonAdminPasswords=false

#Password changing options
echo -e "\033[38;2;16;74;247mChange regular user passwords? (Non-System users) [1]-Yes, [2]-No\033[0m"
read -r changeNonAdminPass
if [ "$changeNonAdminPass" -eq 1 ]; then
    echo "editAdminNonPasswords was set to true"
    editNonAdminPasswords=true
elif [ "$changeNonAdminPass" -eq 2 ]; then
    echo "editAdminNonPasswords was set to false"
    editNonAdminPasswords=false
else
    echo "Invalid option."
fi

echo -e "\033[38;2;16;74;247mChange admin passwords? (Non-System users) [1]-Yes, [2]-No\033[0m"
read -r changeAdminPass
if [ "$changeAdminPass" -eq 1 ]; then
    echo "editAdminPasswords was set to true"
    editAdminPasswords=true
elif [ "$changeAdminPass" -eq 2 ]; then
    echo "editAdminPasswords was set to false"
    editAdminPasswords=false
else
    echo "Invalid option."
fi

echo -e '\033[38;2;16;74;247mDo you want to select a custom password? (Default is "Password123!") [1]-Yes, [2]-No\033[0m'
read -r changeAdminPass
if [ "$changeAdminPass" -eq 1 ]; then

    echo -e "\033[38;2;16;74;247mEnter in the password -->\033[0m"
    read -r changedPass
    echo "PASSWORD was set to $changedPass"
    PASSWORD = "$changedPass"

elif [ "$changeAdminPass" -eq 2 ]; then
    echo "editAdminPasswords was set to false"
    editAdminPasswords=false
else
    echo "Invalid option."
fi

#Cool Stuff to change passwords
for user in $(awk -F: '($3>=1000)&&($1!="nobody"){print $1}' /etc/passwd); do
    if sudo getent shadow | grep -Po '^[^:]*(?=:.?:)' | grep -qw "$user"; then
        # Check if the user is in the "adm" group
        if groups "$user" | grep -qw "adm"; then
            if $editAdminPasswords; then
                echo -e "$PASSWORD\n$PASSWORD" | sudo passwd "$user"
                echo "Password for admin user $user updated."
            fi
        else
            if $editNonAdminPasswords; then
                echo -e "$PASSWORD\n$PASSWORD" | sudo passwd "$user"
                echo "Password for non-admin user $user updated."
            fi
        fi
    fi
done
}

findMedia() {
sudo apt install mlocate
sudo updatedb

echo -e " "
echo -e "\033[1;31m| Suspicous Files |\033[0m"
echo -e "\033[1;31mV                 V\033[0m"
echo -e " "
#seaches for suspicous files
locate -i "nmap|metasploit|aircrack-ng|john|nc|netcat|evil|winrm|ophcrack|vnc|deluge|doas|ettercap|wireshark|tshark|nmap|ncat|tcpdump|hping3|aircrack|airmon|arpspoof|burp|ripper|hydra|medusa|sqlmap|nikto|metasploit|msfconsole|beef|sshpass|telnet|snort|openvas|vuls|yara|shodan|theharvester|setoolkit|msfvenom|recon|binwalk|hashcat|binutils|strace|lsof|whois|wfuzz|wpscan|psexec"
echo -e " "
echo -e " "
echo -e "\033[1;34m| Media Files |\033[0m"
echo -e "\033[1;34mV             V\033[0m"
echo -e " "
#seaches for media files
locate -i "spotify|discord|mines|minetest|minecraft|roblox|sudoku|aisleriot|quadrapassel|chess|puzzle|lightsoff|mahjongg|iagno|klotski|nibbles|snake|reversi|gnometris|tetris|pong|robots|foop|tetravex|tali|0ad|openra|dosbox|warzone|retroarch|trachmania|pinball|arcade|poker|roulette|shooter|music|kingdom|war|steam|battlenet|ubisoft|manaplus|gameconqueror"
}

#Options
echo -e "\033[38;2;16;74;247mWhat Mode? [1]-Run Full Script, [2]-Find Viruses and Media, [3]-Edit User Passwords [4]-Exit Pulse Program\033[0m"
read -r mode

if [ "$mode" -eq 1 ]; then
    echo "Running Full Script..."
    fullScript
elif [ "$mode" -eq 2 ]; then
    echo "Finding Viruses and Media..."
    findMedia
elif [ "$mode" -eq 3 ]; then
    echo "Changing Passwords..."
    fillUserPasswords
elif [ "$mode" -eq 4 ]; then
    echo "Exiting Pulse Program..."
    exit 0
else
    echo "Invalid option."
fi