package main

// Import your packages
import (
	"fmt"
	"log"
	"os"
	"unsafe"

	"github.com/kardianos/service"
	"golang.org/x/sys/windows"
)

const (
	PROCESS_ALL_ACCESS              = 0x1F0FFF
	MEM_COMMIT                      = 0x1000
	SE_ASSIGNPRIMARYTOKEN_NAME      = "SeAssignPrimaryTokenPrivilege"
	SE_LOAD_DRIVER_NAME             = "SeLoadDriverPrivilege"
	SE_SYSTEM_ENVIRONMENT_NAME      = "SeSystemEnvironmentPrivilege"
	SE_TAKE_OWNERSHIP_NAME          = "SeTakeOwnershipPrivilege"
	SE_DEBUG_NAME                   = "SeDebugPrivilege"
	SE_TCB_NAME                     = "SeTcbPrivilege"
	SE_INCREASE_QUOTA_NAME          = "SeIncreaseQuotaPrivilege"
	SE_SECURITY_NAME                = "SeSecurityPrivilege"
	SE_SYSTEMTIME_NAME              = "SeSystemtimePrivilege"
	SE_BACKUP_NAME                  = "SeBackupPrivilege"
	SE_RESTORE_NAME                 = "SeRestorePrivilege"
	SE_SHUTDOWN_NAME                = "SeShutdownPrivilege"
	SE_UNDOCK_NAME                  = "SeUndockPrivilege"
	SE_MANAGE_VOLUME_NAME           = "SeManageVolumePrivilege"
	SE_CREATE_TOKEN_NAME            = "SeCreateTokenPrivilege"
	SE_TRUSTED_CRED_MAN_ACCESS_NAME = "SeTrustedCredManAccessPrivilege"

	LOGON32_PROVIDER_DEFAULT      = 0
	LOGON32_LOGON_INTERACTIVE     = 2
	CREATE_UNICODE_ENVIRONMENT    = 0x00000400
	FORMAT_MESSAGE_FROM_SYSTEM    = 0x00001000
	FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x00002000
	FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200
)

func runWithPrivileges(targetFunc func() (uint32, error)) {
	// Enable the required privileges
	privileges := []string{
		SE_ASSIGNPRIMARYTOKEN_NAME,
		SE_LOAD_DRIVER_NAME,
		SE_SYSTEM_ENVIRONMENT_NAME,
		SE_TAKE_OWNERSHIP_NAME,
		SE_DEBUG_NAME,
		SE_TCB_NAME,
		SE_INCREASE_QUOTA_NAME,
		SE_SECURITY_NAME,
		SE_SYSTEMTIME_NAME,
		SE_BACKUP_NAME,
		SE_RESTORE_NAME,
		SE_SHUTDOWN_NAME,
		SE_UNDOCK_NAME,
		SE_MANAGE_VOLUME_NAME,
		SE_CREATE_TOKEN_NAME,
		SE_TRUSTED_CRED_MAN_ACCESS_NAME,
	}

	for _, privilege := range privileges {
		err := enablePrivilege(privilege)
		if err != nil {
			log.Fatalf("Failed to enable %s: %v", privilege, err)
		}
	}

	// Run the provided function with the required privileges
	_, _ = targetFunc()
}

func enablePrivilege(privilegeName string) error {
	var token windows.Token
	currentProcess, _ := windows.GetCurrentProcess()
	err := windows.OpenProcessToken(currentProcess, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)

	if err != nil {
		return err
	}
	defer token.Close()

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(privilegeName), &luid)
	if err != nil {
		return err
	}

	privileges := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{
				Luid:       luid,
				Attributes: windows.SE_PRIVILEGE_ENABLED,
			},
		},
	}

	err = windows.AdjustTokenPrivileges(token, false, &privileges, 0, nil, nil)

	if err != nil && err != windows.ERROR_NOT_ALL_ASSIGNED {
		return err
	}

	return nil
}

type patriotService struct {
	Service      service.Service
	guiProcessId int
}

func (s *patriotService) run() {
	s.runPatriot()
}
func (s *patriotService) Stop(service.Service) error {
	// Here, you can add any cleanup code or stop any long-running operations
	if s.guiProcessId != 0 {
		// Open the process
		processHandle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(s.guiProcessId))
		if err != nil {
			log.Printf("Failed to open process: %v", err)
			return err
		}
		// Terminate the process
		err = windows.TerminateProcess(processHandle, 0)
		if err != nil {
			log.Printf("Failed to terminate process: %v", err)
			return err
		}
	}
	return nil
}
func (s *patriotService) runPatriot() {
	fmt.Println("Ensuring adequate privileges")
	fmt.Println("(-)Booting up the PowerShell... please wait X) -- Coded By Harrison Edwards")
	runWithPrivileges(func() (uint32, error) {
		pid, err := s.startGUI()
		if err != nil {
			log.Fatalf("Failed to start PowerShell: %v", err)
		}
		s.guiProcessId = int(pid)
		return pid, err
	})
}
func (s *patriotService) Start(service.Service) error {
	go s.run()
	return nil
}
func (s *patriotService) startGUI() (uint32, error) {
	// Change from "patriot-gui.exe" to "PowerShell.exe"
	cmdLine := windows.StringToUTF16Ptr("powershell.exe -File C:\\Path\\To\\Your\\Script.ps1")

	// Get current process token
	currentProcess, _ := windows.GetCurrentProcess()
	var currentProcessToken windows.Token
	err := windows.OpenProcessToken(currentProcess, windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ASSIGN_PRIMARY, &currentProcessToken)
	if err != nil {
		log.Fatalf("Failed to get current process token: %v", err)
	}

	// Duplicate the current process token with TOKEN_ALL_ACCESS to create a primary token
	var duplicatedToken windows.Token
	err = windows.DuplicateTokenEx(currentProcessToken, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityIdentification, windows.TokenPrimary, &duplicatedToken)
	if err != nil {
		log.Fatalf("Failed to duplicate token: %v", err)
	}

	// Get the user session ID
	sessionID := windows.WTSGetActiveConsoleSessionId()

	// Set the token session ID to the active session
	sessionIDBytes := (*byte)(unsafe.Pointer(&sessionID))
	err = windows.SetTokenInformation(duplicatedToken, windows.TokenSessionId, sessionIDBytes, uint32(unsafe.Sizeof(sessionID)))

	if err != nil {
		log.Fatalf("Failed to set token information: %v", err)
	}

	// Get the user environment block
	var envBlock *uint16
	err = windows.CreateEnvironmentBlock(&envBlock, duplicatedToken, false)
	if err != nil {
		return 0, fmt.Errorf("Failed to create environment block: %w", err)
	}

	// Define the process startup information
	si := new(windows.StartupInfo)
	si.Cb = uint32(unsafe.Sizeof(*si))
	si.Flags = windows.STARTF_USESHOWWINDOW
	si.ShowWindow = windows.SW_SHOWDEFAULT
	si.Desktop = windows.StringToUTF16Ptr("Winsta0\\Default") // new line here

	// Create the process
	pi := new(windows.ProcessInformation)
	err = windows.CreateProcessAsUser(duplicatedToken, nil, cmdLine, nil, nil, false, windows.CREATE_UNICODE_ENVIRONMENT, envBlock, nil, si, pi)
	if err != nil {
		return 0, fmt.Errorf("Failed to create process: %w", err)
	}

	return uint32(pi.ProcessId), nil
}
func main() {
	svcConfig := &service.Config{
		Name:        "PatriotService",
		DisplayName: "The Patriot Service",
		Description: "This is The Patriot Service.",
	}

	p := &patriotService{}
	s, err := service.New(p, svcConfig)
	if err != nil {
		log.Fatal(err)
	}
	p.Service = s

	logger, err := s.Logger(nil)
	if err != nil {
		log.Fatal(err)
	}

	if len(os.Args) > 1 {
		err := service.Control(s, os.Args[1])
		if err != nil {
			log.Printf("Valid actions: %q\n", service.ControlAction)
			log.Fatal(err)
		}
		return
	}

	err = s.Run()
	if err != nil {
		logger.Error(err)
	}
}
