package openvex

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/getreeldev/reel-vex/pkg/db"
)

// TestComponent_SubcomponentsParsed confirms the parser captures the OpenVEX
// 0.2.0 subcomponent struct (Rancher VEX shape) and that CollectIdentifiers
// deliberately does NOT descend into it — the product @id and the subcomponent
// carry different meaning (scope vs. matchable package) and are walked
// separately by the Rancher adapter.
func TestComponent_SubcomponentsParsed(t *testing.T) {
	const doc = `{
	  "@context": "https://openvex.dev/ns/v0.2.0",
	  "statements": [{
	    "vulnerability": {"name": "CVE-2024-1"},
	    "products": [{
	      "@id": "pkg:oci/longhorn-engine?repository_url=registry.suse.com/rancher/longhorn-engine",
	      "subcomponents": [{"@id": "pkg:golang/golang.org/x/net@v0.17.0"}]
	    }],
	    "status": "not_affected",
	    "justification": "vulnerable_code_not_present"
	  }]
	}`

	var d Document
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(d.Statements) != 1 {
		t.Fatalf("statements: got %d, want 1", len(d.Statements))
	}
	prods := d.Statements[0].Products
	if len(prods) != 1 {
		t.Fatalf("products: got %d, want 1", len(prods))
	}
	if len(prods[0].Subcomponents) != 1 {
		t.Fatalf("subcomponents: got %d, want 1", len(prods[0].Subcomponents))
	}
	if got := prods[0].Subcomponents[0].ID; got != "pkg:golang/golang.org/x/net@v0.17.0" {
		t.Errorf("subcomponent @id: got %q", got)
	}

	// CollectIdentifiers returns only the product @id — never the subcomponent.
	ids := CollectIdentifiers(prods)
	if len(ids) != 1 || ids[0] != "pkg:oci/longhorn-engine?repository_url=registry.suse.com/rancher/longhorn-engine" {
		t.Errorf("CollectIdentifiers should yield only the product @id, got %v", ids)
	}
}

// TestEncode_ScopeInStatusNotes confirms a product-scoped row discloses its
// scope in status_notes (as `scope=…`), while an unscoped row never does.
func TestEncode_ScopeInStatusNotes(t *testing.T) {
	const scope = "pkg:oci/longhorn-engine?repository_url=registry.suse.com/rancher/longhorn-engine"
	stmts := []db.Statement{
		{Vendor: "rancher", CVE: "CVE-2024-1", ProductID: "pkg:golang/golang.org/x/net@v0.17.0", BaseID: "pkg:golang/golang.org/x/net", IDType: "purl", Status: "not_affected", Justification: "vulnerable_code_not_present", SourceFormat: "openvex", Scope: scope},
		{Vendor: "redhat", CVE: "CVE-2024-1", ProductID: "pkg:rpm/redhat/x@1", BaseID: "pkg:rpm/redhat/x", IDType: "purl", Status: "fixed", SourceFormat: "csaf"},
	}
	doc := Encode(stmts, nil, nil)

	var scoped, unscoped *Statement
	for i := range doc.Statements {
		switch doc.Statements[i].Supplier {
		case "rancher":
			scoped = &doc.Statements[i]
		case "redhat":
			unscoped = &doc.Statements[i]
		}
	}
	if scoped == nil || unscoped == nil {
		t.Fatalf("expected rancher + redhat statements, got %d", len(doc.Statements))
	}
	if !strings.Contains(scoped.StatusNotes, "scope="+scope) {
		t.Errorf("scoped row should disclose scope, got status_notes=%q", scoped.StatusNotes)
	}
	if strings.Contains(unscoped.StatusNotes, "scope=") {
		t.Errorf("unscoped row must not carry scope=, got status_notes=%q", unscoped.StatusNotes)
	}
}
