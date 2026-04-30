package openvex

import (
	"reflect"
	"testing"
)

func TestCollectIdentifiers(t *testing.T) {
	tests := []struct {
		name     string
		products []Component
		want     []string
	}{
		{
			name:     "empty list returns nil",
			products: nil,
			want:     nil,
		},
		{
			name: "single @id",
			products: []Component{
				{ID: "pkg:rpm/redhat/log4j"},
			},
			want: []string{"pkg:rpm/redhat/log4j"},
		},
		{
			name: "all four scheme fields collected",
			products: []Component{
				{
					ID: "pkg:rpm/redhat/log4j",
					Identifiers: &Identifiers{
						PURL:  "pkg:rpm/redhat/log4j-purl",
						CPE22: "cpe:/a:redhat:log4j",
						CPE23: "cpe:2.3:a:redhat:log4j:*",
					},
				},
			},
			want: []string{
				"pkg:rpm/redhat/log4j",
				"pkg:rpm/redhat/log4j-purl",
				"cpe:/a:redhat:log4j",
				"cpe:2.3:a:redhat:log4j:*",
			},
		},
		{
			name: "@id and identifiers.purl identical → single entry",
			products: []Component{
				{
					ID:          "pkg:rpm/redhat/log4j",
					Identifiers: &Identifiers{PURL: "pkg:rpm/redhat/log4j"},
				},
			},
			want: []string{"pkg:rpm/redhat/log4j"},
		},
		{
			name: "duplicates across products dedup",
			products: []Component{
				{ID: "pkg:rpm/redhat/log4j"},
				{ID: "pkg:rpm/redhat/log4j"},
			},
			want: []string{"pkg:rpm/redhat/log4j"},
		},
		{
			name: "whitespace-only entries dropped",
			products: []Component{
				{ID: "  "},
				{Identifiers: &Identifiers{PURL: ""}},
				{ID: "pkg:rpm/x"},
			},
			want: []string{"pkg:rpm/x"},
		},
		{
			name: "products with no identifiers → empty result",
			products: []Component{
				{},
				{Identifiers: &Identifiers{}},
			},
			want: nil,
		},
		{
			name: "Canonical OpenVEX shape (deb PURL with arch+distro)",
			products: []Component{
				{ID: "pkg:deb/ubuntu/linux@4.15.0-1199.214~14.04.1?arch=source&distro=esm-infra-legacy/trusty"},
			},
			want: []string{"pkg:deb/ubuntu/linux@4.15.0-1199.214~14.04.1?arch=source&distro=esm-infra-legacy/trusty"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CollectIdentifiers(tc.products)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
