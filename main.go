package main

import (
	"fmt"
	seccomp "github.com/seccomp/libseccomp-golang"
	"syscall"
)

func main() {
	if err := loadSeccompFilter(); err != nil {
		fmt.Println(fmt.Sprintf("Failed to load seccomp filter: %v", err))
		return
	}

	const dirPath = "/tmp/info"
	// Running the whitelisted code
	if err := syscall.Mkdir(dirPath, 0600); err != nil {
		fmt.Printf("Failed creating directory: %v\n", err)
		return
	}
	fmt.Printf("Directory %q created successfully\n", dirPath)

	// Trying to run non whitelisted syscall
	fmt.Println("Trying to get current working directory")
	wd, err := syscall.Getwd()
	if err != nil {
		fmt.Printf("Failed getting current working directory: %v\n", err)
		return
	}
	fmt.Printf("Current working directory is: %s\n", wd)
}

func loadSeccompFilter() error {
	whitelist := []string{
		"futex", "mkdirat", "nanosleep", "readlinkat",
		"write", "mmap", "fcntl", "sigaltstack",
		"rt_sigprocmask", "arch_prctl", "gettid",
		"read", "close", "rt_sigaction", "clone",
		"execve", "uname", "mlock", "sched_getaffinity", "openat",
	}

	// The filter defaults to fail all syscalls
	filter, err := seccomp.NewFilter(seccomp.ActErrno.SetReturnCode(int16(syscall.EPERM)))
	if err != nil {
		return err
	}
	// Whitelist relevant syscalls and load the filter
	for _, name := range whitelist {
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
