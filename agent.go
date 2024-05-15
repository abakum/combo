/*
MIT License

Copyright (c) 2023-2024 The Trzsz SSH Authors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh/agent"
)

type xAgent struct {
	client     agent.ExtendedAgent
	conn       net.Conn
	forwarding func()
	connClose  func()
}

var (
	agentOnce       sync.Once
	agentClient     agent.ExtendedAgent
	agentForwarding func()
	agentConnClose  func()
	agents          = make(map[string]*xAgent)
)

func getIdentityAgentAddr(args *sshArgs, param *sshParam) (string, error) {
	if addr := getOptionConfig(args, "IdentityAgent"); addr != "" {
		if strings.ToLower(addr) == "none" {
			return "", nil
		}
		if strings.HasPrefix(addr, "$") {
			s := strings.TrimPrefix(addr, "$")
			s = strings.Trim(s, "{}")
			return os.Getenv(s), nil
		}
		expandedAddr, err := expandTokens(addr, args, param, "%CdhijkLlnpru")
		if err != nil {
			return "", fmt.Errorf("expand IdentityAgent [%s] failed: %v", addr, err)
		}
		return resolveHomeDir(expandedAddr), nil
	}
	if addr := os.Getenv("SSH_AUTH_SOCK"); addr != "" {
		return resolveHomeDir(addr), nil
	}
	if addr := defaultAgentAddr; addr != "" && isFileExist(addr) {
		return addr, nil
	}
	return "", nil
}

func getForwardAgentAddr(args *sshArgs, param *sshParam) (string, error) {
	if args.NoForwardAgent {
		return "", nil
	}
	if addr := getOptionConfig(args, "ForwardAgent"); addr != "" {
		switch strings.ToLower(addr) {
		case "none":
			return "", nil
		case "yes":
			return getIdentityAgentAddr(args, param)
		}
		if strings.HasPrefix(addr, "$") {
			s := strings.TrimPrefix(addr, "$")
			s = strings.Trim(s, "{}")
			return os.Getenv(s), nil
		}
		addr = resolveHomeDir(addr)
		if isFileExist(addr) {
			return addr, nil
		}
	}
	if args.ForwardAgent {
		return getIdentityAgentAddr(args, param)
	}
	return "", nil
}

func getAgentClient(args *sshArgs, param *sshParam) agent.ExtendedAgent {
	agentOnce.Do(func() {
		addr, err := getIdentityAgentAddr(args, param)
		if err != nil {
			warning("get agent addr failed: %v", err)
			return
		}
		if addr == "" {
			debug("ssh agent address is not set")
			return
		}

		conn, err := dialAgent(addr)
		if err != nil {
			debug("dial ssh agent [%s] failed: %v", addr, err)
			return
		}

		agentClient = agent.NewClient(conn)
		debug("new ssh agent client [%s] success", addr)

		agentConnClose = func() {
			debug("connection to the authentication agent closed")
			conn.Close()
			agentClient = nil
		}

	})
	return agentClient
}

func getForwardAgentClient(args *sshArgs, param *sshParam) agent.ExtendedAgent {

	addr, err := getForwardAgentAddr(args, param)
	if err != nil {
		warning("get forward agent addr failed: %v", err)
		return nil
	}
	if addr == "" {
		debug("forward agent address is not set")
		return nil
	}
	ag, ok := agents[addr]
	if ok {
		return ag.client
	}
	ag = new(xAgent)

	conn, err := dialAgent(addr)
	if err != nil {
		debug("dial forward agent [%s] failed: %v", addr, err)
		return nil
	}
	ag.conn = conn

	ag.client = agent.NewClient(conn)
	debug("new forward agent client [%s] success", addr)

	ag.connClose = func() {
		debug("connection to the forward agent %s closed", addr)
		ag.conn.Close()
		ag.client = nil
	}
	agents[addr] = ag
	return ag.client
}
