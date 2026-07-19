package bleeplab

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestSHAUTHLogoutClaimIsAtomicAcrossReplicas(t *testing.T) {
	root := t.TempDir()
	first, err := newSHAUTHStateStore(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newSHAUTHStateStore(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	claim := shauthLogoutClaim{
		Issuer: "https://auth.dev.e6qu.dev/", ClientID: "client", JTI: "one-use",
		SID: "sid-1", Issued: now, Expires: now.Add(5 * time.Minute),
	}
	results := make(chan bool, 2)
	errors := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	start := make(chan struct{})
	for _, store := range []*shauthStateStore{first, second} {
		go func(store *shauthStateStore) {
			ready.Done()
			<-start
			claimed, err := store.claimLogout(claim, now)
			results <- claimed
			errors <- err
		}(store)
	}
	ready.Wait()
	close(start)
	claimed := 0
	for range 2 {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
		if <-results {
			claimed++
		}
	}
	if claimed != 1 {
		t.Fatalf("atomic claim winners = %d, want exactly 1", claimed)
	}
	restarted, err := newSHAUTHStateStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if replayAccepted, err := restarted.claimLogout(claim, now); err != nil || replayAccepted {
		t.Fatalf("replay after restart accepted=%t err=%v", replayAccepted, err)
	}
}

func TestSHAUTHLogoutClaimDoesNotRevokeLaterSessionReusingSID(t *testing.T) {
	store, err := newSHAUTHStateStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	claim := shauthLogoutClaim{
		Issuer: "https://auth.dev.e6qu.dev/", ClientID: "client", JTI: "old-session",
		SID: "sid-1", Issued: now, Expires: now.Add(5 * time.Minute),
	}
	if claimed, err := store.claimLogout(claim, now); err != nil || !claimed {
		t.Fatalf("claim logout token: claimed=%t err=%v", claimed, err)
	}
	session := shauthSession{
		Issuer: claim.Issuer, ClientID: claim.ClientID, Subject: "subject-1", SID: claim.SID,
		IDToken: "signed.id.token", Role: "developer", Created: now.Add(500 * time.Millisecond), Expires: now.Add(time.Hour),
	}
	id, err := store.createSession(session)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists, err := store.session(id, now.Add(time.Second)); err != nil || !exists {
		t.Fatalf("later session was revoked by older sid claim: exists=%t err=%v", exists, err)
	}
}

func TestSHAUTHStateRejectsTrailingJSONCorruption(t *testing.T) {
	store, err := newSHAUTHStateStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	session := shauthSession{
		Issuer: "https://auth.dev.e6qu.dev/", ClientID: "client", Subject: "subject-1",
		IDToken: "signed.id.token", Role: "developer", Created: time.Now().UTC(), Expires: time.Now().Add(time.Hour),
	}
	id, err := store.createSession(session)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.sessionsDir, id+".json")
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(`{"second":"value"}`); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.session(id, time.Now()); err == nil {
		t.Fatal("session with trailing JSON value was accepted")
	}
}
