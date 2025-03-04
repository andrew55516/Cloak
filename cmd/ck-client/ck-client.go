//go:build go1.11
// +build go1.11

package main

import (
	"encoding/binary"
	"github.com/cbeuw/Cloak/internal/client"
	"github.com/cbeuw/Cloak/internal/common"
	mux "github.com/cbeuw/Cloak/internal/multiplex"
	log "github.com/sirupsen/logrus"
	"net"
	"sync"
)

type CkClient struct {
	mu        sync.Mutex
	connected bool
	config    *client.RawConfig
	session   *mux.Session
}

func NewCkClient(config *client.RawConfig) *CkClient {
	return &CkClient{config: config}
}

func (c *CkClient) Connect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		log.Println("ck-client already connected")
		return
	}
	c.connected = true
	log.Println("ck-client connected")

	localConfig, remoteConfig, authInfo, err := c.config.ProcessRawConfig(common.RealWorldState)
	if err != nil {
		log.Fatal(err)
	}

	var adminUID []byte
	if len(c.config.UID) != 0 {
		adminUID = c.config.UID
		//log.Printf("Cloak/ck-client.go: adminUID set to %s", adminUID)
	}

	var seshMaker func() *mux.Session

	d := &net.Dialer{Control: protector, KeepAlive: remoteConfig.KeepAlive}

	if adminUID != nil {
		log.Infof("API base is %v", localConfig.LocalAddr)
		authInfo.UID = adminUID
		authInfo.SessionId = 0
		remoteConfig.NumConn = 1

		seshMaker = func() *mux.Session {
			c.session = client.MakeSession(remoteConfig, authInfo, d)
			return c.session
		}
	} else {
		var network string
		if authInfo.Unordered {
			network = "UDP"
		} else {
			network = "TCP"
		}
		log.Infof("Listening on %v %v for %v client", network, localConfig.LocalAddr, authInfo.ProxyMethod)
		seshMaker = func() *mux.Session {
			authInfo := authInfo // copy the struct because we are overwriting SessionId

			randByte := make([]byte, 1)
			common.RandRead(authInfo.WorldState.Rand, randByte)
			authInfo.MockDomain = localConfig.MockDomainList[int(randByte[0])%len(localConfig.MockDomainList)]

			// sessionID is usergenerated. There shouldn't be a security concern because the scope of
			// sessionID is limited to its UID.
			quad := make([]byte, 4)
			common.RandRead(authInfo.WorldState.Rand, quad)
			authInfo.SessionId = binary.BigEndian.Uint32(quad)
			c.session = client.MakeSession(remoteConfig, authInfo, d)
			return c.session
		}
	}

	if authInfo.Unordered {
		acceptor := func() (*net.UDPConn, error) {
			udpAddr, _ := net.ResolveUDPAddr("udp", localConfig.LocalAddr)
			return net.ListenUDP("udp", udpAddr)
		}

		client.RouteUDP(acceptor, localConfig.Timeout, remoteConfig.Singleplex, seshMaker)
	} else {
		listener, err := net.Listen("tcp", localConfig.LocalAddr)
		if err != nil {
			log.Fatal(err)
		}
		client.RouteTCP(listener, localConfig.Timeout, remoteConfig.Singleplex, seshMaker)
	}
}

func (c *CkClient) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		log.Println("ck-client not connected")
		return
	}
	c.connected = false

	if c.session != nil {
		c.session.Close()
		log.Printf("ck-client session closed")
	}

	log.Println("ck-client disconnected")
}

func InitLog() {
	log_init()
}
