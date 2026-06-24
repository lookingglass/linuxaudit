#!/usr/bin/env bash

set -euo pipefail

VERBOSE=false

function usage() {
	FILENAME=$(basename "$0")
	cat <<EOU >&2
$FILENAME Usage:

$FILENAME --help            Display help
$FILENAME --verbose         Print all checks. Without --verbose flag excludes OK message 
EOU
}

#utils

function print_ok {
	if [[ $VERBOSE == "true" ]]; then
		echo "[OK] $1"
	fi
}

function print_low {
	echo "[LOW] $1"
}

function print_medium {
	echo "[MEDIUM] $1"
}

function print_high {
	echo "[HIGH] $1"
}

function print_critical {
	echo "[CRITICAL] $1"
}

function is_root {

	if [[ $EUID -ne 0 ]]; then
		return 1
	else
		return 0
	fi

}

function detect_os {
	source /etc/os-release
	case $ID in
	fedora | rhel)
		echo "rhel"
		;;
	debian | ubuntu)
		echo "debian"
		;;
	*)
		echo "other"
		;;
	esac
}

function get_ip {
	ip=$(ip -4 route show default | awk '{print $9}')
	echo "$ip"
}

# security checks

function check_password_auth {
	if is_root; then
		CONFIG_VALUE=$(sshd -T | grep "passwordauthentication" | awk '{print $2}')
		if [[ "$CONFIG_VALUE" == "no" ]]; then
			print_ok "Auth by password is disabled."
		else

			print_medium "Auth by password is enabled."
		fi
	fi

}

function check_root_login {

	if is_root; then
		CONFIG_VALUE=$(sshd -T | grep "permitrootlogin" | awk '{print $2}')
		if [[ "$CONFIG_VALUE" == "yes" ]]; then
			print_medium "Logging as root is enabled."
		else
			print_ok "Logging as root is disabled"
		fi
	fi
}

function check_if_allowed_empty_passwords {
	if is_root; then
		CONFIG_VALUE=$(sshd -T | grep "permitemptypasswords" | awk '{print $2}')
		if [[ "$CONFIG_VALUE" == "no" ]]; then
			print_ok "Empty passwords are not allowed."
		else
			print_critical "Empty passwords ARE ALLOWED"
		fi
	fi
}

function check_ssh_port {
	if ss -tulpn | grep "sshd" >/dev/null; then
		if ss -tulpn | grep "sshd" | grep ":22" >/dev/null; then
			print_low "sshd is running on default port."
		else
			print_ok "sshd is running on diffrent port."
		fi
	else
		print_ok "sshd is not found."
	fi
}

## Additional checks
# Docker checks

function check_docker_group_privileges {
	check_perms=$(getent group docker | awk -F':' '{print $4}')
	if [[ -z "$check_perms" ]]; then
		print_ok "No users found in group 'docker'."
	else
		print_high "Users found in group 'docker': $check_perms. Potential privilege escalation via host escape."
	fi
}

function check_docker_privileged_containers {
	if docker ps -q | xargs docker inspect --format '{{.HostConfig.Privileged}}' | grep true >/dev/null; then
		print_high "Found priveleged container(s). Potential privilege escalation via host escape."
	else
		print_ok "No privileged containers found"
	fi
}

# ufw

function check_ufw {
	if ufw status 2>/dev/null | head -n1 2>/dev/null; then
		print_ok "ufw is running"
	else
		print_medium "ufw is not running"
	fi
}

# fail2ban

function check_fail2ban {
	if systemctl is-active -q fail2ban.service; then
		print_ok "fail2ban enabled"
	else
		print_medium "fail2ban is not enabled"
	fi
}

## distro-specific checks
# Debian checks

function check_apparmor {
	apparmor_status=$(cat /sys/module/apparmor/parameters/enabled)
	if [[ "$apparmor_status" == "Y" ]]; then
		print_ok "Apparmor is enabled."
	else
		print_low "Apparmor is disabled."
	fi
}

# RHEL checks

function check_selinux {
	selinux_status=$(sestatus | grep "Current mode" | awk '{print $3}')
	if [[ "$selinux_status" == "permissive" || "$selinux_status" == "disabled" ]]; then
		print_low "SELinux is disabled."
	else
		print_ok "SELinux is enabled"
	fi
}

function check_firewalld {
	if systemctl is-active -q firewalld; then
		print_ok "firewalld is running."
	else
		print_low "firewalld is not active."
	fi
}

# execute
function execute {
	OS_TYPE=$(detect_os)
	echo -e "\n==========================================="
	echo -e "Audit for: $(hostname) ($(get_ip))"
	echo -e "===========================================\n"

	check_ssh_port
	check_password_auth
	check_root_login
	if [[ $(command -v docker) ]]; then
		check_docker_privileged_containers
		check_docker_group_privileges
	fi
	if [[ $(command -v ufw) ]]; then
		check_ufw
	fi

	if [[ $(command -v fail2ban-client) ]]; then
		check_fail2ban
	fi

	check_if_allowed_empty_passwords

	if [[ "$OS_TYPE" == "rhel" ]]; then
		check_selinux
		check_firewalld
	fi
	if [[ "$OS_TYPE" == "debian" ]]; then
		check_apparmor
	fi
	if ! is_root; then
		echo "Some checks was skipped because root required"
	fi
}

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
