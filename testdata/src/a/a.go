package a

import (
	"net/url"
	"reflect"
	"testing"
)

func FuzzOKTest(f *testing.F) {
	f.Add("x=1&y=2")
	f.Fuzz(func(t *testing.T, queryStr string) {
		query, err := url.ParseQuery(queryStr)
		if err != nil {
			t.Skip()
		}
		queryStr2 := query.Encode()
		query2, err := url.ParseQuery(queryStr2)
		if err != nil {
			t.Fatalf("ParseQuery failed to decode a valid encoded query %s: %v", queryStr2, err)
		}
		if !reflect.DeepEqual(query, query2) {
			t.Errorf("ParseQuery gave different query after being encoded\nbefore: %v\nafter: %v", query, query2)
		}
	})

}

func FuzzNGTest(f *testing.F) { // want "There is no corpus on FuzzNGTest's fuzzing test."
	f.Fuzz(func(t *testing.T, queryStr string) {
		query, err := url.ParseQuery(queryStr)
		if err != nil {
			t.Skip()
		}
		queryStr2 := query.Encode()
		query2, err := url.ParseQuery(queryStr2)
		if err != nil {
			t.Fatalf("ParseQuery failed to decode a valid encoded query %s: %v", queryStr2, err)
		}
		if !reflect.DeepEqual(query, query2) {
			t.Errorf("ParseQuery gave different query after being encoded\nbefore: %v\nafter: %v", query, query2)
		}
	})

}
