package cluster

import (
	"encoding/json"
	"net"
	"strconv"
	"sync/atomic"
	"time"
)

type Responder struct {
	connection *net.UDPConn
	running    atomic.Bool
}

func StartResponder(port int, bind string, info func() Obj) (*Responder, error) {
	address, err := net.ResolveUDPAddr("udp", net.JoinHostPort(bind, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	connection, err := net.ListenUDP("udp", address)
	if err != nil {
		return nil, err
	}
	responder := &Responder{connection: connection}
	responder.running.Store(true)
	go func() {
		buffer := make([]byte, 4096)
		for responder.running.Load() {
			_ = connection.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			count, sender, err := connection.ReadFromUDP(buffer)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
			message, err := DecodeObj(buffer[:count])
			if err != nil || message["who"] != true {
				continue
			}
			data, _ := json.Marshal(info())
			_, _ = connection.WriteToUDP(data, sender)
		}
	}()
	return responder, nil
}

func (r *Responder) Port() int { return r.connection.LocalAddr().(*net.UDPAddr).Port }

func (r *Responder) Stop() {
	r.running.Store(false)
	_ = r.connection.Close()
}

type Target struct {
	Host string
	Port int
}

func Probe(targets []Target, wait time.Duration, bind string) []Obj {
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(bind), Port: 0})
	if err != nil {
		return nil
	}
	defer listener.Close()
	replyPort := listener.LocalAddr().(*net.UDPAddr).Port
	found := map[string]Obj{}
	var order []string
	deadline := time.Now().Add(wait)
	var sent time.Time
	for time.Now().Before(deadline) {
		if time.Since(sent) > time.Second {
			request, _ := json.Marshal(Obj{"who": true, "reply": replyPort})
			for _, target := range targets {
				if destination, err := net.ResolveUDPAddr("udp", net.JoinHostPort(target.Host, strconv.Itoa(target.Port))); err == nil {
					_, _ = listener.WriteToUDP(request, destination)
				}
			}
			sent = time.Now()
		}
		_ = listener.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buffer := make([]byte, 4096)
		count, _, err := listener.ReadFromUDP(buffer)
		if err != nil {
			continue
		}
		info, err := DecodeObj(buffer[:count])
		if err != nil {
			continue
		}
		if address, ok := info["addr"].(string); ok {
			if _, seen := found[address]; !seen {
				order = append(order, address)
			}
			found[address] = info
		}
	}
	replies := make([]Obj, 0, len(order))
	for _, address := range order {
		replies = append(replies, found[address])
	}
	return replies
}
