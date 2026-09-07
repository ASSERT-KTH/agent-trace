package models

type ActionType string

const (
	FileOpen    ActionType = "file_open"
	FileRead    ActionType = "file_read"
	FileWrite   ActionType = "file_write"
	FileClose   ActionType = "file_close"
	FileRename  ActionType = "file_rename"
	FileDelete  ActionType = "file_delete"
	NetRequest  ActionType = "net_request"
	NetDNS      ActionType = "net_dns"
	NetConnect  ActionType = "net_connect"
	ProcessExec ActionType = "process_exec"
	ProcessExit ActionType = "process_exit"
	GitCommit   ActionType = "git_commit"
)

var validActionTypes = map[ActionType]bool{
	FileOpen:    true,
	FileRead:    true,
	FileWrite:   true,
	FileClose:   true,
	FileRename:  true,
	FileDelete:  true,
	NetRequest:  true,
	NetDNS:      true,
	NetConnect:  true,
	ProcessExec: true,
	ProcessExit: true,
	GitCommit:   true,
}

func (a ActionType) IsValid() bool {
	return validActionTypes[a]
}
