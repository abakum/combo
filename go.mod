module github.com/abakum/combo

go 1.21.4

replace internal/tool => ./internal/tool

replace github.com/ThalesIgnite/crypto11 v1.2.5 => github.com/blacknon/crypto11 v1.2.6

require (
	github.com/Microsoft/go-winio v0.6.1
	github.com/abakum/embed-encrypt v0.0.0-20240330115809-059354cfa29a
	github.com/abakum/go-ansiterm v0.0.0-20240209124652-4fc46d492442
	github.com/abakum/go-console v0.0.0-20231203133515-5d1e7fd8831f
	github.com/abakum/go-netstat v0.0.0-20231106075911-001f10558dcf
	github.com/abakum/menu v0.0.0-20240212125241-bf7578ad1b3a
	github.com/abakum/pageant v0.0.0-20240210190511-4450a30bb403
	github.com/abakum/version v0.1.3-lw
	github.com/abakum/winssh v0.0.0-20240415133556-bafe6ee0f83e
	github.com/gliderlabs/ssh v0.3.7
	github.com/xlab/closer v1.1.0
	golang.org/x/crypto v0.19.0
	golang.org/x/sys v0.18.0
	internal/tool v0.0.0-00010101000000-000000000000
)

require (
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/creack/pty v1.1.21 // indirect
	github.com/eiannone/keyboard v0.0.0-20220611211555-0d226195f203 // indirect
	github.com/fatih/color v1.16.0 // indirect
	github.com/iamacarpet/go-winpty v1.0.4 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	github.com/pkg/sftp v1.13.6 // indirect
	golang.org/x/mod v0.14.0 // indirect
	golang.org/x/tools v0.16.0 // indirect
)