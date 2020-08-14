package main

import (
	"fmt"
	seccomp "github.com/seccomp/libseccomp-golang"
	"syscall"
)

func main() {
	err := loadSeccompFilter()
	if err != nil {
		fmt.Println(fmt.Sprintf("Failed to load seccomp filter: %v", err))
		return
	}

	// Running the whitelisted code
	err = syscall.Mkdir("/tmp/info", 0600)
	if err != nil {
		fmt.Println(fmt.Sprintf("Failed creating folder: %v", err))
		return
	}
	fmt.Println("Folder created successfully")

	// Trying to run non permitted syscalls
	fmt.Println("Trying to get current working directory")
	wd, err := syscall.Getwd()
	if err != nil {
		fmt.Println(fmt.Sprintf("Failed getting current working directory: %v", err))
		return
	}
	fmt.Println(fmt.Sprintf("Current working directory is: %s", wd))
}

func loadSeccompFilter() error {
	// The filter defaults to fail all syscalls
	filter, err := seccomp.NewFilter(seccomp.ActErrno.SetReturnCode(int16(syscall.EPERM)))
	if err != nil {
		return err
	}
	// Whitelist relevant syscalls and load the filter
	for _, name := range []string{
		"futex", "mkdirat", "nanosleep", "readlinkat",
		"write", "mmap", "fcntl", "sigaltstack",
		"rt_sigprocmask", "arch_prctl", "gettid",
		"read", "close", "rt_sigaction", "clone",
		"execve", "uname", "mlock", "sched_getaffinity", "openat",
	} {
		syscallID, err := seccomp.GetSyscallFromName(name)
		if err != nil {
			return err
		}
		err = filter.AddRule(syscallID, seccomp.ActAllow)
		if err != nil {
			return err
		}
	}
	return filter.Load()
}
