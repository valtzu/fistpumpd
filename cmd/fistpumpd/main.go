package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/valtzu/fistpumpd/cluster"
)

var version = "dev"

const (
	runDirectory     = "/run/fistpumpd"
	stateDirectory   = "/var/lib/fistpumpd"
	genesisPath      = "/usr/lib/fistpumpd/genesis.json"
	buildCertificate = "/usr/lib/verity.d/mkosi.crt"
)

var topologyPaths = []string{"/etc/fistpumpd/topology.json", "/usr/lib/fistpumpd/topology.json"}
var keyrings = []string{"/usr/lib/systemd/import-pubring.pgp", "/usr/lib/systemd/import-pubring.gpg"}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	command, arguments := os.Args[1], os.Args[2:]
	var err error
	switch command {
	case "daemon":
		err = runDaemon(arguments)
	case "status":
		err = status()
	case "log":
		err = printLog()
	case "evict":
		err = evict(arguments)
	case "reset-sign":
		err = resetSign(arguments)
	case "submit":
		err = submit(arguments)
	case "verify":
		err = verify(arguments)
	case "version":
		fmt.Println(version)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fistpumpd:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: fistpumpd daemon | status | log | evict NODE [--reason TEXT] | reset-sign --log FILE --key FILE --certificate FILE --keep SLOTS | submit FILE | verify [--certificate FILE] < log.json | version")
	os.Exit(2)
}

func defaultRoute() (string, string) {
	output, _ := exec.Command("ip", "-4", "-o", "route", "get", "1.1.1.1").Output()
	device := regexp.MustCompile(`dev (\S+)`).FindStringSubmatch(string(output))
	source := regexp.MustCompile(`src (\S+)`).FindStringSubmatch(string(output))
	iface, address := "eth0", ""
	if device != nil {
		iface = device[1]
	}
	if source != nil {
		address = source[1]
	}
	return iface, address
}

func firstExisting(paths []string) string {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return paths[0]
}

func runDaemon(arguments []string) error {
	flags := flag.NewFlagSet("daemon", flag.ExitOnError)
	state := flags.String("state", stateDirectory, "state directory")
	genesisFile := flags.String("genesis", genesisPath, "genesis file")
	topology := flags.String("topology", "", "topology file")
	_ = flags.Parse(arguments)
	var candidates []string
	if *topology == "" {
		candidates, *topology = topologyPaths, firstExisting(topologyPaths)
	}
	genesis, err := cluster.LoadGenesis(*genesisFile)
	if err != nil {
		return err
	}
	iface, source := defaultRoute()
	if source == "" {
		return fmt.Errorf("no default route yet")
	}
	certificate, _ := os.ReadFile(buildCertificate)
	keyring := firstExisting(keyrings)
	cache := filepath.Join(*state, "policy")
	daemon, err := cluster.NewDaemon(cluster.DaemonConfig{
		Paths:   cluster.Paths{State: *state, Run: runDirectory, Topology: *topology, Topologies: candidates, Credstore: cluster.DefaultCredstore},
		Genesis: genesis, TPM: &cluster.TPMProver{}, Verifier: cluster.TPMVerifier{}, Address: fmt.Sprintf("%s:%d", source, genesis.Port),
		BuildCertificate: certificate, Interface: iface, Seal: true,
		Targets: []cluster.Target{{Host: "255.255.255.255", Port: genesis.DiscoveryPort}},
		PolicyLoader: func() (cluster.Obj, error) {
			return cluster.RefreshPolicy(genesis.PolicyURLs, keyring, cache, cluster.HTTPOpener)
		},
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	err = daemon.Run(ctx)
	daemon.Stop()
	return err
}

func control(method string, payload cluster.Obj) (cluster.Obj, error) {
	return cluster.ControlCall(filepath.Join(runDirectory, "control.sock"), method, payload)
}

func status() error {
	reply, err := control("status", cluster.Obj{})
	if err != nil {
		return err
	}
	state, _ := reply["status"].(cluster.Obj)
	fmt.Printf("phase %v  slot %v  topology v%v  log length %v\n", state["phase"], reply["slot"], reply["topology"], reply["length"])
	failing, _ := reply["failing"].(cluster.Obj)
	members, _ := reply["members"].([]any)
	for _, item := range members {
		member := item.(cluster.Obj)
		node, _ := member["node"].(cluster.Obj)
		health := "ok"
		if _, bad := failing[fmt.Sprint(member["slot"])]; bad {
			health = "failing"
		}
		roles := strings.Join(toStrings(member["roles"]), ",")
		if roles == "" {
			roles = "-"
		}
		fmt.Printf("  node %-3v (slot %v) %-22v roles %-24s %s\n", member["number"], member["slot"], node["addr"], roles, health)
	}
	roleList, _ := reply["roles"].([]any)
	for _, item := range roleList {
		role := item.(cluster.Obj)
		upper := "any"
		if limit, bounded := role["max"]; bounded {
			upper = fmt.Sprint(limit)
		}
		fmt.Printf("  role %-12v want %v..%-4s held %-3v ready %v\n", role["name"], role["min"], upper, role["held"], role["ready"])
	}
	return nil
}

func toStrings(value any) []string {
	var list []string
	items, _ := value.([]any)
	for _, item := range items {
		list = append(list, fmt.Sprint(item))
	}
	return list
}

func printLog() error {
	reply, err := control("log", cluster.Obj{})
	if err != nil {
		return err
	}
	data, _ := json.MarshalIndent(reply, "", "  ")
	fmt.Println(string(data))
	return nil
}

func evict(arguments []string) error {
	flags := flag.NewFlagSet("evict", flag.ExitOnError)
	reason := flags.String("reason", "operator request", "reason")
	positional, flagArguments := splitFlags(arguments)
	_ = flags.Parse(flagArguments)
	if len(positional) != 1 {
		usage()
	}
	number, err := strconv.Atoi(positional[0])
	if err != nil {
		return err
	}
	reply, err := control("evict", cluster.Obj{"number": number, "reason": *reason})
	if err != nil {
		return err
	}
	data, _ := json.Marshal(reply)
	fmt.Println(string(data))
	return nil
}

func splitFlags(arguments []string) ([]string, []string) {
	var positional, flagged []string
	for index := 0; index < len(arguments); index++ {
		if strings.HasPrefix(arguments[index], "-") {
			flagged = append(flagged, arguments[index])
			if !strings.Contains(arguments[index], "=") && index+1 < len(arguments) {
				index++
				flagged = append(flagged, arguments[index])
			}
		} else {
			positional = append(positional, arguments[index])
		}
	}
	return positional, flagged
}

func resetSign(arguments []string) error {
	flags := flag.NewFlagSet("reset-sign", flag.ExitOnError)
	logFile := flags.String("log", "", "log JSON from a surviving member")
	keyFile := flags.String("key", "", "build key (PEM)")
	certFile := flags.String("certificate", "", "build certificate (PEM)")
	keep := flags.String("keep", "", "comma-separated slots that stay")
	reason := flags.String("reason", "operator reset", "reason")
	_ = flags.Parse(arguments)
	if *logFile == "" || *keyFile == "" || *certFile == "" || *keep == "" {
		usage()
	}
	data, err := os.ReadFile(*logFile)
	if err != nil {
		return err
	}
	document, err := cluster.Decode(data)
	if err != nil {
		return err
	}
	var entries []any
	switch typed := document.(type) {
	case cluster.Obj:
		entries, _ = typed["entries"].([]any)
	case []any:
		entries = typed
	}
	certificate, err := os.ReadFile(*certFile)
	if err != nil {
		return err
	}
	chain := cluster.NewChain(certificate)
	for _, entry := range entries {
		if err := chain.Append(entry.(cluster.Obj)); err != nil {
			return err
		}
	}
	var slots []string
	for _, slot := range strings.Split(*keep, ",") {
		slots = append(slots, strings.TrimSpace(slot))
	}
	sort.Strings(slots)
	members := []any{}
	for _, slot := range slots {
		number, err := strconv.Atoi(slot)
		if err != nil {
			return err
		}
		members = append(members, number)
	}
	entry := cluster.Obj{"index": chain.Len(), "prev": chain.Head(), "type": "reset", "body": cluster.Obj{"members": members, "reason": *reason}}
	keyData, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		return fmt.Errorf("%s: no PEM block", *keyFile)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			return err
		}
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return fmt.Errorf("the build key cannot sign")
	}
	if entry["build_sig"], err = cluster.SignBuild(signer, entry); err != nil {
		return err
	}
	if err := chain.Check(entry); err != nil {
		return err
	}
	fmt.Println(string(cluster.Marshal(entry)))
	return nil
}

func submit(arguments []string) error {
	if len(arguments) != 1 {
		usage()
	}
	data, err := os.ReadFile(arguments[0])
	if err != nil {
		return err
	}
	entry, err := cluster.DecodeObj(data)
	if err != nil {
		return err
	}
	reply, err := control("submit", cluster.Obj{"entry": entry})
	if err != nil {
		return err
	}
	out, _ := json.Marshal(reply)
	fmt.Println(string(out))
	return nil
}

func verify(arguments []string) error {
	flags := flag.NewFlagSet("verify", flag.ExitOnError)
	certFile := flags.String("certificate", "", "build certificate (PEM), needed to accept reset entries")
	_ = flags.Parse(arguments)
	var certificate []byte
	if *certFile != "" {
		var err error
		if certificate, err = os.ReadFile(*certFile); err != nil {
			return err
		}
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<20))
	if err != nil {
		return err
	}
	document, err := cluster.Decode(data)
	if err != nil {
		return err
	}
	var entries []any
	switch typed := document.(type) {
	case cluster.Obj:
		entries, _ = typed["entries"].([]any)
	case []any:
		entries = typed
	}
	chain := cluster.NewChain(certificate)
	for _, item := range entries {
		entry, ok := item.(cluster.Obj)
		if !ok {
			return fmt.Errorf("an entry is an object")
		}
		if err := chain.Append(entry); err != nil {
			return fmt.Errorf("entry %v: %v", entry["index"], err)
		}
	}
	out, _ := json.Marshal(cluster.Summarize(chain))
	fmt.Println(string(out))
	return nil
}
