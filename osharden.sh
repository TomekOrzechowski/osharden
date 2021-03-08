#!/bin/bash

function sysctl () {
  local file=$1
  local parameter=$2
  local value=$3
  local r1=$(echo "$parameter" | sed 's/\./\\./g')

  [ -d /etc/sysctl.d ] || mkdir -p /etc/sysctl.d
  [ -r /etc/sysctl.d/$file ] || touch /etc/sysctl.d/$file
  for f in /etc/sysctl.conf /etc/sysctl.d/*; do
    if [ -f "$f" ] && grep -q "^$r1[[:blank:]]*=" "$f"; then
        if [ "$f" == "/etc/sysctl.d/$file" ]; then
            grep "^$r1[[:blank:]]*=[[:blank:]]*" "$f" |\
              grep -q -v "=[[:blank:]]*$value$" && \
              sed -i "s/^\($r1\)[[:blank:]]*=.*/\1=$value/" "$f"
        else
            sed -i "s/^\($r1[[:blank:]]*=.*\)/#\1/" "$f"
        fi
    fi
  done

  if ! grep -q "^$r1[[:blank:]]*=" /etc/sysctl.conf /etc/sysctl.d/*; then
    echo $parameter=$value >> /etc/sysctl.d/$file
  fi

}

sysctl 10-network-security.conf net.ipv4.conf.default.rp_filter 1
sysctl 10-network-security.conf net.ipv4.conf.all.rp_filter 1
sysctl 10-network-security.conf net.ipv4.conf.default.secure_redirects 0
sysctl 10-network-security.conf net.ipv4.conf.default.accept_redirects 0
sysctl 10-network-security.conf net.ipv4.conf.all.log_martians 1

function modprobe_conf() {
  local file=$1
  local command=$2
  local modulename=$3
  local opts=$4
  local r1=$(echo "$command $modulename "|sed 's/[[:blank:]]\+/[[:blank:]]\\+/g')

  for f in /etc/modprobe.d/*; do
    if [ -f "$f" ] && grep -q "^$r1" "$f"; then
        if [ "$f" == "/etc/modprobe.d/$file" ]; then
            grep "^$r1" "$f" | grep -q -v "^$r1$opts" && \
              sed -i "s/^\($r1).*/\1 $opts/" "$f"
        else
            sed -i "s/^\($r1.*)/#\1/" "$f"
        fi
    fi
  done

  if ! grep -q "^$r1$opts" /etc/modprobe.d/*; then
    echo $command $modulename $opts >> /etc/modprobe.d/$file
  fi

}

modprobe_conf filesystems.conf install cramfs /bin/true
modprobe_conf filesystems.conf install hfs /bin/true
modprobe_conf filesystems.conf install jffs2 /bin/true
modprobe_conf filesystems.conf install hfsplus /bin/true
modprobe_conf filesystems.conf install freevxfs /bin/true
modprobe_conf filesystems.conf install rds /bin/true
exit

# 1.
if [ -f /etc/sysconfig/network ]; then
    if ! grep -q '^NOZEROCONF[[:blank:]]*=.*' /etc/sysconfig/network; then
        echo 'NOZEROCONF=yes' >> /etc/sysconfig/network
    else
	grep '^NOZEROCONF[[:blank:]]*=.*' /etc/sysconfig/network | grep -q -v 'yes' &&\
          sed -i 's/^\(NOZEROCONF[[:blank:]]*=[[:blank:]]*\).*/\1yes/' /etc/sysconfig/network
    fi
fi

# 4.
if [ -f /etc/samba/smb.conf ]; then
    if grep '^[[:blank:]]*\(server \|\)min\ protocol[[:blank:]]*=' /etc/samba/smb.conf | grep -q -v 'SMB[23]'; then
        sed -i '/^\[global\]$/,/^\[/ s/^\([[:blank:]]*\(server \|\)min\ protocol[[:blank:]]*=\).*/\1 SMB2/' /etc/samba/smb.conf
    fi
    grep -q '^[[:blank:]]*\(server \|\)min\ protocol[[:blank:]]*=.*' /etc/samba/smb.conf || \
        sed -i '/^\[global\]$/a \\tmin protocol = SMB2' /etc/samba/smb.conf
fi

# 5.
for f in /etc/ssh/sshd_config /etc/ssh/ssh_config.d/*; do
    if [ -f "$f" ]; then
        grep '^[[:blank:]]*HostbasedAuthentication[[:blank:]]\+' "$f" | grep -q -v 'no' &&\
            sed -i 's/^\([[:blank:]]*HostbasedAuthentication[[:blank:]]\+\).*/\1no/' "$f"
    fi
done

grep -q '^[[:blank:]]*HostbasedAuthentication[[:blank:]]\+' /etc/ssh/sshd_config /etc/ssh/ssh_config.d/* ||\
    echo 'HostbasedAuthentication no' >> /etc/ssh/sshd_config

# 6.
for f in /etc/ssh/sshd_config /etc/ssh/ssh_config.d/*; do
    if [ -f "$f" ]; then
        grep '^[[:blank:]]*IgnoreRhosts[[:blank:]]\+' "$f" | grep -q -v 'yes' &&\
            sed -i 's/^\([[:blank:]]*IgnoreRhosts[[:blank:]]\+\).*/\1yes/' "$f"
    fi
done

grep -q '^[[:blank:]]*IgnoreRhosts[[:blank:]]\+' /etc/ssh/sshd_config /etc/ssh/ssh_config.d/* ||\
    echo 'IgnoreRhosts yes' >> /etc/ssh/sshd_config

# 7.
for f in /etc/rsyslog.conf /etc/rsyslog.d/*; do
    if [ -f "$f" ]; then
        grep '^$FileCreateMode[[:blank:]]*' "$f" | grep -q -v '06[04]0' &&\
	    sed -i 's/^\($FileCreateMode[[:blank:]]*\).*/\1 0640' "$f"
    fi
done

grep -q '^$FileCreateMode[[:blank:]]*' /etc/rsyslog.conf ||\
    echo '$FileCreateMode 0640' >> /etc/rsyslog.conf

# 8.
echo 'blacklist rds' > /etc/modprobe.d/rds.conf

# 9.
for f in /etc/ssh/sshd_config /etc/ssh/ssh_config.d/*; do
    if [ -f "$f" ]; then
        grep '^[[:blank:]]*Protocol[[:blank:]]\+' "$f" | grep -q -v '2' &&\
            sed -i 's/^\([[:blank:]]*Protocol[[:blank:]]\+\).*/\1 2/' "$f"
    fi
done

grep -q '^[[:blank:]]*Protocol[[:blank:]]\+' /etc/ssh/sshd_config /etc/ssh/ssh_config.d/* ||\
    echo 'Protocol 2' >> /etc/ssh/sshd_config

# 10.
if ! grep -q '^PASS_MIN_DAYS[[:blank:]]\+' /etc/login.defs; then
    echo 'PASS_MIN_DAYS 7' >> /etc/login.defs
else
    grep '^PASS_MIN_DAYS[[:blank:]]\+' /etc/login.defs | grep -q -v '\([7-9]\|[1-9][0-9]\)[[:blank:]]*$' && \
      sed -i 's/^\(PASS_MIN_DAYS[[:blank:]]\+\).*/\1 7/' /etc/login.defs
fi

# 11.
for f in /etc/ssh/sshd_config /etc/ssh/ssh_config.d/*; do
    if [ -f "$f" ]; then
        grep '^[[:blank:]]*PermitEmptyPasswords[[:blank:]]\+' "$f" | grep -q -v 'no' &&\
            sed -i 's/^\([[:blank:]]*PermitEmptyPasswords[[:blank:]]\+\).*/\1no/' "$f"
    fi
done

grep -q '^[[:blank:]]*PermitEmptyPasswords[[:blank:]]\+' /etc/ssh/sshd_config /etc/ssh/ssh_config.d/* ||\
    echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config

# 12.
if ! grep -q '^[[:blank:]]*\(AllowUsers\|AllowGroups\|DenyUsers\|DenyGroups\)[[:blank:]]\+' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*; then
	echo Ensure SSH access is limited !
fi

#NAME All bootloaders should have password protection enabled.
#CCEID CCE-3818-2
#RULE SEVERITY Warning
#FULL DESCRIPTION All bootloaders should have password protection enabled.
#POTENTIAL IMPACT An attacker with physical access could modify bootloader options, yielding unrestricted system access
#ACTUAL VALUE File /boot/grub2/grub.cfg should contain one or more lines matching ['^password\s+--encrypted\s+\S+']
#
#NAME Access to the root account via su should be restricted to the 'root' group
#CCEID CCE-15047-4
#RULE SEVERITY Critical
#FULL DESCRIPTION Access to the root account via su should be restricted to the 'root' group
#POTENTIAL IMPACT An attacker could escalate permissions by password guessing if su is not restricted to users in the root group.
#ACTUAL VALUE File /etc/pam.d/su should contain one or more lines matching ['^[\s\t]*auth\s+required\s+pam_wheel.so(\s+.*)?\suse_uid']
#
#NAME Ensure permissions on bootloader config are configured
#RULE SEVERITY Critical
#FULL DESCRIPTION Ensure permissions on bootloader config are configured
#POTENTIAL IMPACT Setting the permissions to read and write for root only prevents non-root users from seeing the boot parameters or changing them. Non-root users who read the boot parameters may be able to identify weaknesses in security upon boot and be able to exploit them.
#ACTUAL VALUE File '/boot/grub2/grub.cfg' has ownership/permissions errors: Mode is too permissive. Have 644, but want at least 400

[ -f /boot/grub2/grub.cfg ] && chmod 400 /boot/grub2/grub.cfg

#NAME All rsyslog log files should be owned by the syslog user.
#CCEID CCE-17857-4
#RULE SEVERITY Critical
#FULL DESCRIPTION All rsyslog log files should be owned by the syslog user.
#POTENTIAL IMPACT An attacker could cover up activity by manipulating logs
#ACTUAL VALUE File /etc/rsyslog.conf should contain one or more lines matching ['^[\s]*.FileOwner\s+syslog']
for f in /etc/rsyslog.conf /etc/rsyslog.d/*; do
    if [ -f "$f" ]; then
        grep '^$FileOwner[[:blank:]]*' "$f" | grep -q -v ' syslog' &&\
	    sed -i 's/^\($FileOwner[[:blank:]]*\).*/\1 syslog' "$f"
    fi
done

grep -q '^$FileOwner[[:blank:]]*' /etc/rsyslog.conf ||\
    echo '$FileOwner syslog' >> /etc/rsyslog.conf
#
#NAME Postfix network listening should be disabled as appropriate.
#CCEID CCE-15018-5
#RULE SEVERITY Critical
#FULL DESCRIPTION Postfix network listening should be disabled as appropriate.
#POTENTIAL IMPACT An attacker could use this system to send emails with malicious content to other users
#ACTUAL VALUE File /etc/postfix/main.cf should contain one or more lines matching ['^[\s\t]*inet_interfaces\s+localhost\s*$']
#
#[ -r /etc/postfix/main.cf ] && sed -i 's/^\([[:blank:]]*inet_interfaces[[:blank:]]\+.*)/#\1/' /etc/postfix/main.cf
#[ -r /etc/postfix/main.cf ] && echo "inet_interfaces localhost" >> /etc/postfix/main.cf

#NAME /etc/passwd- file permissions should be set to 0600
#CCEID CCE-3932-1
#RULE SEVERITY Critical
#FULL DESCRIPTION /etc/passwd- file permissions should be set to 0600
#POTENTIAL IMPACT An attacker could join security groups if this file is not properly secured
#ACTUAL VALUE File '/etc/passwd-' has ownership/permissions errors: Mode is '644' but should be '600'

[ -f /etc/passwd- ] && chmod 600 /etc/passwd-

#
#NAME The postfix package should be uninstalled.
#CCEID CCE-14068-1
#RULE SEVERITY Critical
#FULL DESCRIPTION The postfix package should be uninstalled.
#POTENTIAL IMPACT An attacker could use this system to send emails with malicious content to other users
#ACTUAL VALUE Package postfix should not be installed
[ -x /usr/bin/apt-get ] && apt-get -y remove postfix
[ -x /usr/bin/yum ] && yum -y remove postfix
#
#NAME The portmap service should be disabled.
#CCEID CCE-4550-0
#RULE SEVERITY Critical
#FULL DESCRIPTION The portmap service should be disabled.
#POTENTIAL IMPACT An attacker could use a flaw in portmap to gain access
#ACTUAL VALUE Service 'rpcbind.service' is not disabled
systemctl stop rpcbind.service
systemctl disable rpcbind.service
systemctl mask rpcbind.service
#
#NAME SSH warning banner should be enabled. - '/etc/ssh/sshd_config Banner = /etc/issue.net'
#CCEID CCE-4431-3
#RULE SEVERITY N/A
for f in /etc/ssh/sshd_config /etc/ssh/ssh_config.d/*; do
    if [ -f "$f" ]; then
        grep '^[[:blank:]]*Banner[[:blank:]]\+' "$f" | grep -q -v '/etc/issue.net' &&\
            sed -i 's/^\([[:blank:]]*Banner[[:blank:]]\+\).*/\= /etc/issue.net/' "$f"
    fi
done

grep -q '^[[:blank:]]*Banner[[:blank:]]\+' /etc/ssh/sshd_config /etc/ssh/ssh_config.d/* ||\
    echo 'Banner = /etc/issue.net' >> /etc/ssh/sshd_config
