#!/usr/bin/env bash


function ctrl_c(){
    echo -e "\n\n${redColour}[+] Exiting the function...${endColour}\n"
    exit 1
}


# Ctrl+C
trap ctrl_c SIGINT

# Colors
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"
whiteColour="\e[0;97m\033[1m"

function show_help(){
    local script_name
    script_name="$(basename "$0")"

    echo "Usage: $script_name [OPTIONS]"
    echo
    echo "Mitigate dirty frag by creating /etc/modprobe.d/dirtyfrag.conf"
    echo
    echo "Options:"
    echo "  -h, --help       Show this help menu"
    echo "  -c, --check      Check mitigation status (no root required)"
    echo "  -r, --rollback   Remove /etc/modprobe.d/dirtyfrag.conf"
    echo
    echo "Examples:"
    echo "  sudo ./$script_name"
    echo "  ./$script_name --check"
    echo "  sudo ./$script_name --rollback"
    echo "  ./$script_name --help"
}

action="apply"

function check_status(){
    local conf_file="/etc/modprobe.d/dirtyfrag.conf"
    local has_esp4="no"
    local has_esp6="no"
    local has_rxrpc="no"
    local loaded_any="no"

    if grep -qE '^esp4 ' /proc/modules 2>/dev/null; then loaded_any="yes"; fi
    if grep -qE '^esp6 ' /proc/modules 2>/dev/null; then loaded_any="yes"; fi
    if grep -qE '^rxrpc ' /proc/modules 2>/dev/null; then loaded_any="yes"; fi

    if [[ -f "$conf_file" ]]; then
        if grep -qE '^[[:space:]]*install[[:space:]]+esp4[[:space:]]+/bin/false([[:space:]]|$)' "$conf_file"; then has_esp4="yes"; fi
        if grep -qE '^[[:space:]]*install[[:space:]]+esp6[[:space:]]+/bin/false([[:space:]]|$)' "$conf_file"; then has_esp6="yes"; fi
        if grep -qE '^[[:space:]]*install[[:space:]]+rxrpc[[:space:]]+/bin/false([[:space:]]|$)' "$conf_file"; then has_rxrpc="yes"; fi
    fi

    echo -e "${blueColour}[*] Checking dirtyfrag mitigation status (non-root check mode)...${endColour}"
    echo -e "${blueColour}[*] Config file:${endColour} $conf_file"
    echo -e "${blueColour}[*] install esp4 /bin/false:${endColour} $has_esp4"
    echo -e "${blueColour}[*] install esp6 /bin/false:${endColour} $has_esp6"
    echo -e "${blueColour}[*] install rxrpc /bin/false:${endColour} $has_rxrpc"
    echo -e "${blueColour}[*] Any vulnerable modules currently loaded:${endColour} $loaded_any"

    if [[ "$has_esp4" == "yes" && "$has_esp6" == "yes" && "$has_rxrpc" == "yes" && "$loaded_any" == "no" ]]; then
        echo -e "${greenColour}[+] Likely mitigated against dirtyfrag based on module blocklist and load state.${endColour}"
        echo -e "${yellowColour}[*] Note:${endColour} This same module-level mitigation also reduces fragnesia exposure on the same ESP/XFRM surface."
        echo -e "${yellowColour}[*] Note:${endColour} Fragnesia is a separate bug with its own patch, but shares mitigation surface with dirtyfrag."
    else
        echo -e "${redColour}[-] Not fully mitigated based on current non-root checks.${endColour}"
        echo -e "${yellowColour}[*] Recommendation:${endColour} ensure dirtyfrag.conf has install rules for esp4/esp6/rxrpc and unload active modules as root."
    fi
}

case "$1" in
    -h|--help)
        show_help
        exit 0
        ;;
    -c|--check)
        action="check"
        ;;
    -r|--rollback)
        action="rollback"
        ;;
    "")
        ;;
    *)
        echo -e "${redColour}[-] Invalid option: $1${endColour}"
        echo
        show_help
        exit 1
        ;;
esac

if [ "$action" = "check" ]; then
    check_status
    exit 0
fi


if [ "$(id -u)" -ne 0 ]; then
    echo -e "${redColour}[-] Please run this script as root.${endColour}"
    exit 1
fi

if [ "$action" = "rollback" ]; then
    if [ -f /etc/modprobe.d/dirtyfrag.conf ]; then
        echo -e "${redColour}[!] Warning: rolling back changes. This will make you vulnerable again.${endColour}"
        rm -f /etc/modprobe.d/dirtyfrag.conf
        wait
        echo -e "${greenColour}[+] Changes rolled back successfully.${endColour}"
    else
        echo -e "${yellowColour}[*] Nothing to roll back. dirtyfrag.conf was not found.${endColour}"
    fi
    exit 0
fi

if [ -f /etc/modprobe.d/dirtyfrag.conf ]; then
    echo -e "${yellowColour}[*] dirtyfrag.conf already exists, skipping creation.${endColour}"
    exit 0
fi

cat <<-EOF > /etc/modprobe.d/dirtyfrag.conf
install esp4 /bin/false
install esp6 /bin/false
install rxrpc /bin/false
EOF
wait
echo 3 > /proc/sys/vm/drop_caches
wait
echo -e "${greenColour}[+] dirtyfrag.conf created successfully.${endColour}"
cat /etc/modprobe.d/dirtyfrag.conf
