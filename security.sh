#!/usr/bin/env bash

set -uo pipefail


VERBOSE=false


#SEVERITY_OK="[OK] "
SEVERITY_LOW="[LOW] "
SEVERITY_MEDIUM="[MEDIUM] "
SEVERITY_HIGH="[HIGH] "
SEVERITY_CRITICAL="[CRITICAL] "


function usage()
{
    FILENAME=$(basename "$0")
	cat << EOU >&2
$FILENAME Usage:

$FILENAME --help            Display help
$FILENAME --verbose         Print all checks. Without --verbose flag excludes OK message 
EOU
}

#utils

function print_ok {
    echo "[OK] $1"
}

function is_root {

    if [[ $EUID -ne 0 ]]; then
        return 1
    else
        return 0
    fi

}

function detect_os {
    if [[ -f /etc/debian_version ]]; then
        OS_TYPE="Debian"
    elif [[ -f /etc/redhat-release ]]; then
        OS_TYPE="RHEL"
    else
        OS_TYPE="Other"
    fi
}

function get_ip {
    ip=$(ip -4 route show default | awk '{print $9}')
    echo $ip
}

# security checks

function check_password_auth { 
    if is_root; then
        CONFIG_VALUE=$(sshd -T | grep "passwordauthentication" | awk '{print $2}')
        if [[ "$CONFIG_VALUE" == "no" ]]; then
            [ $VERBOSE == true ] && print_ok "Auth by password is disabled."
        else
            echo "${SEVERITY_MEDIUM}Auth by password is enabled."
        fi
    fi

}

function check_root_login {

    if is_root; then
        CONFIG_VALUE=$(sshd -T | grep "permitrootlogin" | awk '{print $2}')
        if [[ "$CONFIG_VALUE" == "yes" ]]; then
            echo "${SEVERITY_HIGH}Logging as root is enabled."
        else
            [ $VERBOSE == true ] && print_ok "Logging as root is disabled"
        fi
    fi
}


function check_if_allowed_empty_passwords {
        if is_root; then
        CONFIG_VALUE=$(sshd -T | grep "permitemptypasswords" | awk '{print $2}')
        if [[ "$CONFIG_VALUE" == "no" ]]; then
            [ $VERBOSE == true ] && print_ok "Empty passwords are not allowed."
        else
            echo "${SEVERITY_CRITICAL}Empty passwords ARE ALLOWED!!!"
        fi
    fi
}

function check_docker_priveleges {
    check_perms=$(getent group docker | awk -F':' '{print $4}')
    if [[ -z "$check_perms" ]];then
        [ $VERBOSE == true ] && print_ok "No users found in group 'docker'."
    else
        echo "${SEVERITY_MEDIUM}Users found in group 'docker': $check_perms. Potential privelege escalation via host escape."
    fi
}

function check_ssh_port {
    if ss -tulpn | grep "sshd" > /dev/null; then
        if ss -tulpn | grep "sshd" | grep ":22" > /dev/null; then
            echo "${SEVERITY_LOW}sshd is running on default port."
        else
            [ $VERBOSE == true ] && print_ok "sshd is running on diffrent port."
        fi
    else
        [ $VERBOSE == true ] && print_ok "sshd is not found."
    fi
}

## distro-specific checks
# Debian checks

function check_apparmor {
    apparmor_status=$(cat /sys/module/apparmor/parameters/enabled)
    if [[ "$apparmor_status" == "Y" ]]; then
        [ $VERBOSE == true ] && print_ok "Apparmor is enabled."
    else
        echo "${SEVERITY_LOW}Apparmor is disabled."
    fi
}

# RHEL checks

function check_selinux {
    selinux_status=$(sestatus | grep "Current mode" | awk '{print $3}')
    if [[ "$selinux_status" == "permissive" || "$selinux_status" == "disabled" ]]; then
        echo "${SEVERITY_LOW}SELinux is disabled."
    else
        [ $VERBOSE == true ] && print_ok "SELinux is enabled"
    fi
}

function check_firewalld {
    if systemctl is-active -q firewalld; then
        [ $VERBOSE == true ] && print_ok "firewalld is running."
    else
        echo "${SEVERITY_LOW}firewalld is not active."
    fi   
}

# execute
function execute {
    detect_os
    echo -e "\n==========================================="
    echo -e "Audit for: $(hostname) ($(get_ip))"
    echo -e "===========================================\n"

    check_ssh_port
    check_password_auth 
    check_docker_priveleges
    check_if_allowed_empty_passwords

    if [[ "$OS_TYPE" == "RHEL" ]]; then
        check_selinux
        check_firewalld
    fi
    if [[ "$OS_TYPE" == "Debian" ]]; then
        check_apparmor
    fi
    if ! is_root; then
        echo "Some checks was skipped because root required"
    fi
}

while true
do
	case "${@}" in
		-h | --help)
			usage
			exit 0
			;;
        --verbose)
            VERBOSE=true
            execute
            exit 0
            ;;
		*)
            execute
            exit 0
			;;
	esac
done
