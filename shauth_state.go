package bleeplab

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

type shauthLogoutClaim struct {
	Issuer   string    `json:"issuer"`
	ClientID string    `json:"client_id"`
	JTI      string    `json:"jti"`
	SID      string    `json:"sid,omitempty"`
	Subject  string    `json:"subject,omitempty"`
	Issued   time.Time `json:"issued"`
	Received time.Time `json:"received"`
	Expires  time.Time `json:"expires"`
}

type shauthStateStore struct {
	root        string
	sessionsDir string
	claimsDir   string
}

func newSHAUTHStateStore(root string) (*shauthStateStore, error) {
	store := &shauthStateStore{
		root:        root,
		sessionsDir: filepath.Join(root, "sessions"),
		claimsDir:   filepath.Join(root, "logout-claims"),
	}
	for _, directory := range []string{store.root, store.sessionsDir, store.claimsDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, fmt.Errorf("create Shauth state directory: %w", err)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			return nil, fmt.Errorf("secure Shauth state directory: %w", err)
		}
	}
	return store, nil
}

func (store *shauthStateStore) createSession(session shauthSession) (string, error) {
	for range 4 {
		id, err := randomSHAUTHValue()
		if err != nil {
			return "", err
		}
		path := filepath.Join(store.sessionsDir, id+".json")
		if err := writeAtomicNoReplaceJSON(path, session); err == nil {
			return id, nil
		} else if !errors.Is(err, fs.ErrExist) {
			return "", fmt.Errorf("persist Shauth session: %w", err)
		}
	}
	return "", fmt.Errorf("create unique Shauth session identifier")
}

func (store *shauthStateStore) session(id string, now time.Time) (shauthSession, bool, error) {
	if !validSHAUTHSessionID(id) {
		return shauthSession{}, false, nil
	}
	path := filepath.Join(store.sessionsDir, id+".json")
	var session shauthSession
	if err := readFileJSON(path, &session); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return shauthSession{}, false, nil
		}
		return shauthSession{}, false, fmt.Errorf("read Shauth session: %w", err)
	}
	if !session.Expires.After(now) {
		if err := store.deleteSession(id); err != nil {
			return shauthSession{}, false, err
		}
		return shauthSession{}, false, nil
	}
	revoked, err := store.sessionRevoked(session, now)
	if err != nil {
		return shauthSession{}, false, err
	}
	if revoked {
		if err := store.deleteSession(id); err != nil {
			return shauthSession{}, false, err
		}
		return shauthSession{}, false, nil
	}
	return session, true, nil
}

func (store *shauthStateStore) deleteSession(id string) error {
	if !validSHAUTHSessionID(id) {
		return nil
	}
	err := os.Remove(filepath.Join(store.sessionsDir, id+".json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("delete Shauth session: %w", err)
	}
	if err == nil {
		if err := syncDirectory(store.sessionsDir); err != nil {
			return fmt.Errorf("sync Shauth session deletion: %w", err)
		}
	}
	return nil
}

func (store *shauthStateStore) claimLogout(claim shauthLogoutClaim, now time.Time) (bool, error) {
	claim.Received = now.UTC()
	path := filepath.Join(store.claimsDir, claimFilename(claim)+".json")
	var prior shauthLogoutClaim
	if err := readFileJSON(path, &prior); err == nil {
		if prior.Expires.After(now) {
			return false, nil
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false, fmt.Errorf("expire Shauth logout replay claim: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("read Shauth logout replay claim: %w", err)
	}

	if err := writeAtomicNoReplaceJSON(path, claim); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return false, nil
		}
		return false, fmt.Errorf("atomically claim Shauth logout token: %w", err)
	}
	return true, nil
}

func (store *shauthStateStore) sessionRevoked(session shauthSession, now time.Time) (bool, error) {
	entries, err := os.ReadDir(store.claimsDir)
	if err != nil {
		return false, fmt.Errorf("list Shauth logout claims: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" || entry.Name()[0] == '.' {
			continue
		}
		path := filepath.Join(store.claimsDir, entry.Name())
		var claim shauthLogoutClaim
		if err := readFileJSON(path, &claim); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return false, fmt.Errorf("read Shauth logout claim: %w", err)
		}
		if !claim.Expires.After(now) {
			if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return false, fmt.Errorf("expire Shauth logout claim: %w", err)
			}
			if err := syncDirectory(store.claimsDir); err != nil {
				return false, fmt.Errorf("sync Shauth logout claim expiry: %w", err)
			}
			continue
		}
		if claim.Issuer != session.Issuer || claim.ClientID != session.ClientID {
			continue
		}
		if claim.SID != "" && claim.SID == session.SID && !session.Created.After(claim.Received) {
			return true, nil
		}
		if claim.SID == "" && claim.Subject == session.Subject && !session.Created.After(claim.Received) {
			return true, nil
		}
	}
	return false, nil
}

func validSHAUTHSessionID(id string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(id)
	return err == nil && len(raw) == 32
}

func claimFilename(claim shauthLogoutClaim) string {
	digest := sha256.Sum256([]byte(claim.Issuer + "\x00" + claim.ClientID + "\x00" + claim.JTI))
	return hex.EncodeToString(digest[:])
}

func writeAtomicNoReplaceJSON(path string, value any) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".state-*.json")
	if err != nil {
		return err
	}
	temporaryPath := file.Name()
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
		_ = os.Remove(temporaryPath)
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if err := json.NewEncoder(file).Encode(value); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	closed = true
	if err := os.Link(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}

func readFileJSON(path string, destination any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode %s: %w", filepath.Base(path), err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("decode %s: trailing JSON value", filepath.Base(path))
		}
		return fmt.Errorf("decode %s: %w", filepath.Base(path), err)
	}
	return nil
}
