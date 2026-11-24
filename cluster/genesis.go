package cluster

import (
	"fmt"
	"os"
	stdstrings "strings"
)

const (
	DefaultPort          = 17947
	DefaultDiscoveryPort = 17946
	DefaultAPIPort       = 17948
	DefaultAPIClientCA   = "/etc/fistpumpd/api-client-ca.pem"
)

type Genesis struct {
	MinMembers    int
	Port          int
	DiscoveryPort int
	APIPort       int
	APIClientCAs  []string
	PolicyURLs    []string
	Seeds         []string
	FounderWait   float64
	EvictAfter    float64
	AttestEvery   float64
	JoinRetry     float64
}

func numberField(document Obj, key string, fallback float64) float64 {
	if value, present := document[key]; present {
		if parsed, err := number(value); err == nil {
			return parsed
		}
	}
	return fallback
}

func ParseGenesis(document Obj) (*Genesis, error) {
	genesis := &Genesis{MinMembers: 2, Port: DefaultPort, DiscoveryPort: DefaultDiscoveryPort, APIPort: DefaultAPIPort, APIClientCAs: []string{DefaultAPIClientCA}, FounderWait: 20, EvictAfter: 300, AttestEvery: 30, JoinRetry: 10}
	if value, present := document["min_members"]; present {
		minimum, ok := asInt(value)
		if !ok || minimum < 2 {
			return nil, fmt.Errorf("min_members is at least 2: a lone node never starts a cluster")
		}
		genesis.MinMembers = minimum
	}
	if value, present := document["policy_urls"]; present {
		list, ok := value.([]any)
		if !ok {
			return nil, fmt.Errorf("policy_urls are https URLs")
		}
		for _, item := range list {
			url, isString := item.(string)
			if !isString || !stdstrings.HasPrefix(url, "https://") {
				return nil, fmt.Errorf("policy_urls are https URLs")
			}
			genesis.PolicyURLs = append(genesis.PolicyURLs, url)
		}
	}
	if port, ok := asInt(document["port"]); ok {
		genesis.Port = port
	}
	if port, ok := asInt(document["discovery_port"]); ok {
		genesis.DiscoveryPort = port
	}
	if port, ok := asInt(document["api_port"]); ok {
		genesis.APIPort = port
	}
	if single := str(document, "api_client_ca"); single != "" {
		genesis.APIClientCAs = []string{single}
	} else if list := stringList(document["api_client_ca"]); len(list) > 0 {
		genesis.APIClientCAs = list
	}
	genesis.Seeds = stringList(document["seeds"])
	genesis.FounderWait = numberField(document, "founder_wait", genesis.FounderWait)
	genesis.EvictAfter = numberField(document, "evict_after", genesis.EvictAfter)
	genesis.AttestEvery = numberField(document, "attest_interval", genesis.AttestEvery)
	genesis.JoinRetry = numberField(document, "join_retry", genesis.JoinRetry)
	return genesis, nil
}

func LoadGenesis(path string) (*Genesis, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	document, err := DecodeObj(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	return ParseGenesis(document)
}
