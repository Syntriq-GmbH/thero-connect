package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const protocolDigest = "ea01732824900e9ec1a66ead0200a52c7e7a327680a807a39fcc0724e123c561"

func TestFixturesRoundTrip(t *testing.T) {
	clientSent := map[string]func() any{
		"enroll": func() any { return &enrollMessage{} },
		"hello":  func() any { return &helloMessage{} },
		"page":   func() any { return &pageMessage{} },
		"users":  func() any { return &usersMessage{} },
		"rights": func() any { return &rightsMessage{} },
		"done":   func() any { return &doneMessage{} },
		"renew":  func() any { return &renewMessage{} },
		"error":  func() any { return &errorMessage{} },
	}
	serverSent := []string{"enrolled", "welcome", "walk", "principals", "access", "read", "ack", "cancel", "renewed", "error"}
	files, _ := filepath.Glob("../protocol/v1/fixtures/*.json")
	if len(files) != 17 {
		t.Fatalf("%d fixtures", len(files))
	}
	for _, name := range files {
		kind := strings.TrimSuffix(filepath.Base(name), ".json")
		data, _ := os.ReadFile(name)
		var original map[string]any
		if err := json.Unmarshal(data, &original); err != nil || original["type"] != kind {
			t.Fatalf("%s: type %v, %v", name, original["type"], err)
		}
		_, client := clientSent[kind]
		if !client && !slices.Contains(serverSent, kind) {
			t.Errorf("%s belongs to no direction", name)
		}
		if client {
			value := clientSent[kind]()
			decoder := json.NewDecoder(bytes.NewReader(data))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(value); err != nil {
				t.Errorf("%s: %v", name, err)
				continue
			}
			encoded, _ := json.Marshal(value)
			var again map[string]any
			json.Unmarshal(encoded, &again)
			if !reflect.DeepEqual(original, again) {
				t.Errorf("%s re-encodes as %s", name, encoded)
			}
		}
		if slices.Contains(serverSent, kind) {
			decoder := json.NewDecoder(bytes.NewReader(data))
			decoder.DisallowUnknownFields()
			var m message
			if err := decoder.Decode(&m); err != nil || m.Type != kind {
				t.Errorf("%s: %v", name, err)
			}
		}
	}
}

func TestDigest(t *testing.T) {
	var paths []string
	filepath.WalkDir("../protocol/v1", func(name string, entry fs.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			rel, _ := filepath.Rel("../protocol/v1", name)
			paths = append(paths, filepath.ToSlash(rel))
		}
		return err
	})
	slices.Sort(paths)
	hash := sha256.New()
	for _, rel := range paths {
		data, _ := os.ReadFile(filepath.Join("../protocol/v1", rel))
		hash.Write([]byte(rel + "\x00"))
		hash.Write(data)
		hash.Write([]byte{0})
	}
	if computed := hex.EncodeToString(hash.Sum(nil)); computed != protocolDigest {
		t.Fatalf("protocol digest is %s", computed)
	}
}

func TestChunkLayout(t *testing.T) {
	want, _ := os.ReadFile("../protocol/v1/fixtures/chunk.bin")
	src := newFakeSource()
	f := src.add(`\\fs01\finance\a.txt`, "thero", readable("S-1-1-0"))
	a := testAgent(t, src)
	var frames [][]byte
	reply := a.read(t.Context(), message{Type: "read", ID: 4, Root: "finance", Path: "a.txt", File: "0000000000000001", Size: 5, Modified: f.modified.UnixMilli()}, openWindow(), func(b []byte) error {
		frames = append(frames, bytes.Clone(b))
		return nil
	})
	if _, ok := reply.(doneMessage); !ok || len(frames) != 1 || !bytes.Equal(frames[0], want) {
		t.Fatalf("frames %x, reply %+v, fixture %x", frames, reply, want)
	}
}
