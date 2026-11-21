// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package ssh

import (
	"bufio"
	"net"
	"strconv"
	"strings"
	"time"
)

// Remote ops run through /bin/sh and POSIX tools, so a stock Windows sshd
// (cmd or PowerShell as shell) fails setup. These say what to change there.
const (
	WindowsShellHint = "This is a Windows host, and Shells needs a POSIX shell on it. " +
		"With Git for Windows installed, run this in an administrator PowerShell on that PC, then Retry:\n\n" +
		`New-ItemProperty -Path HKLM:\SOFTWARE\OpenSSH -Name DefaultShell -Value "C:\Program Files\Git\bin\bash.exe" -PropertyType String -Force`
	WindowsAdminKeyHint = "The key was installed, but this Windows host did not accept it: " +
		"for administrator accounts Windows ignores the user's authorized_keys. " +
		`In C:\ProgramData\ssh\sshd_config put a # before the lines "Match Group administrators" and ` +
		`"AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys", run Restart-Service sshd in an administrator PowerShell, then Retry.`
)

// IsWindows reports whether the SSH server at host:port announces itself as
// Windows OpenSSH ("SSH-2.0-OpenSSH_for_Windows_9.5"). The banner comes
// before authentication and in no locale, unlike the shell's error text.
func IsWindows(host string, port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	banner, _ := bufio.NewReaderSize(c, 256).ReadString('\n')
	return strings.Contains(banner, "_for_Windows")
}
