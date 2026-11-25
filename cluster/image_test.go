package cluster

import "testing"

func TestTheImageShownIsTheLatestAttestedOneNotTheAdmissionRecord(t *testing.T) {
	daemon := &Daemon{}
	member := &Member{Slot: 3, Policy: Obj{"image": "35"}}
	if got := daemon.imageOf(member); got != "35" {
		t.Fatalf("before any attestation the admission record is shown, got %q", got)
	}
	daemon.rememberImage(3, "39")
	if got := daemon.imageOf(member); got != "39" {
		t.Fatalf("after attestation the latest image is shown, got %q", got)
	}
	if got := daemon.imageOf(&Member{Slot: 4}); got != "" {
		t.Fatalf("a member never attested has no image, got %q", got)
	}
}
