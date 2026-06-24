# linuxaudit

Small system security audit script // WIP

## Features
- SSH checks (SSH port, PermitRootLogin etc)
- Distro-specific checks (SELinux, AppArmor etc)
- Other checks

## Usage
```bash
./security.sh           

./security.sh --help     Display help
./security.sh --verbose  Print all checks. Without --verbose flag excludes OK message 
```
