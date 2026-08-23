package audit

import (
	"encoding/json"
	"testing"
)

func FuzzPolicyAndSnapshotImports(f *testing.F) {
	f.Add([]byte("policy_schema_version: 1\nname: test\nrules: []\n"))
	f.Add([]byte(`{"snapshot_schema_version":1,"id":"fixture"}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		_, _ = decodePolicy(input)
		var snapshot Snapshot
		if json.Unmarshal(input, &snapshot) == nil {
			_ = validateSnapshot(snapshot)
		}
	})
}
