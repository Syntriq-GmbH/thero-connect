//go:build windows && dfs

package main

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Syntriq-GmbH/thero-connect/core"
)

func TestDfsNamespace(t *testing.T) {
	host := os.Getenv("COMPUTERNAME")
	namespace := `\\` + host + `\ns`
	src := windowsSource{}
	if err := os.MkdirAll(`C:\dfs\docs\sub`, 0o755); err != nil {
		t.Fatal(err)
	}

	entries, err := src.List(namespace)
	if err != nil {
		t.Fatalf("list %s: %v", namespace, err)
	}
	t.Logf("listing of %s: %+v", namespace, entries)
	for _, name := range []string{"docs", "replica"} {
		if !slices.ContainsFunc(entries, func(e core.Entry) bool { return strings.EqualFold(e.Name, name) && e.Dir && e.Link }) {
			t.Errorf("%s is not listed as a link", name)
		}
	}
	if !slices.ContainsFunc(entries, func(e core.Entry) bool { return e.Name == "root.txt" && !e.Dir && !e.Link }) {
		t.Error("root.txt is not listed as a plain file")
	}

	replica, err := src.Referral(namespace + `\replica`)
	t.Logf("referral of replica: %+v %v", replica, err)
	if err != nil || !strings.EqualFold(replica.Consumed, namespace+`\replica`) {
		t.Fatalf("referral of replica: %+v %v", replica, err)
	}
	var shares []string
	for _, target := range slices.Concat(replica.Sets...) {
		shares = append(shares, strings.ToLower(target[strings.LastIndex(target, `\`)+1:]))
	}
	slices.Sort(shares)
	if !slices.Equal(shares, []string{"replicaa", "replicab"}) {
		t.Errorf("replica targets: %+v", replica.Sets)
	}

	docs, err := src.Referral(namespace + `\docs\sub`)
	t.Logf("referral of docs\\sub: %+v %v", docs, err)
	if err != nil || !strings.EqualFold(docs.Consumed, namespace+`\docs`) {
		t.Errorf("referral of docs\\sub: %+v %v", docs, err)
	}

	if _, err := src.Referral(`\\` + host + `\docs`); !errors.Is(err, core.ErrNotFound) {
		t.Errorf("referral of a plain share: %v", err)
	}

	if _, _, err := src.Descriptor(namespace + `\docs\d.txt`); err == nil {
		t.Error("descriptor through a link succeeded")
	} else {
		t.Logf("descriptor through a link: %v", err)
	}
	if _, _, err := src.Descriptor(`\\` + host + `\docs\d.txt`); err != nil {
		t.Errorf("descriptor of the target: %v", err)
	}

	unc := namespace
	for hop := 0; ; hop++ {
		if hop == 2 {
			t.Fatalf("%s is not physical after 2 hops", namespace)
		}
		referral, err := src.Referral(unc)
		t.Logf("hop %d: referral of %s: %+v %v", hop, unc, referral, err)
		if errors.Is(err, core.ErrNotFound) {
			break
		}
		if err != nil {
			t.Fatalf("referral of %s: %v", unc, err)
		}
		if slices.ContainsFunc(referral.Sets[0], func(target string) bool { return strings.EqualFold(target, referral.Consumed) }) {
			break
		}
		unc = referral.Sets[0][0]
	}
}
