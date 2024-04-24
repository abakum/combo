module github.com/abakum/combo

go 1.21.4

replace internal/tool => ./internal/tool

// replace github.com/abakum/winssh => ../winssh

// replace github.com/abakum/go-netstat => ../go-netstat

replace github.com/ThalesIgnite/crypto11 v1.2.5 => github.com/blacknon/crypto11 v1.2.6

require (
	github.com/abakum/embed-encrypt v0.0.0-20240419131915-ba2ccee1a359
	github.com/abakum/go-ansiterm v0.0.0-20240209124652-4fc46d492442
	github.com/abakum/go-netstat v0.0.0-20240420133855-c5cf502094c3
	github.com/abakum/menu v0.0.0-20240419084129-0b97c23cf292
	github.com/abakum/pageant v0.0.0-20240419114114-01633e0d85e4
	github.com/abakum/version v0.1.3-lw
	github.com/abakum/winssh v0.0.0-20240423112316-6b19b2b163ba
	github.com/gliderlabs/ssh v0.3.7
	github.com/magiconair/properties v1.8.7
	github.com/xlab/closer v1.1.0
	golang.org/x/crypto v0.22.0
	golang.org/x/sys v0.19.0
	internal/tool v0.0.0-00010101000000-000000000000
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/abakum/go-console v0.0.0-20240420142043-eda1cdf92473 // indirect
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/creack/pty v1.1.21 // indirect
	github.com/eiannone/keyboard v0.0.0-20220611211555-0d226195f203 // indirect
	github.com/fatih/color v1.16.0 // indirect
	github.com/iamacarpet/go-winpty v1.0.4 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	github.com/pkg/sftp v1.13.6 // indirect
)
