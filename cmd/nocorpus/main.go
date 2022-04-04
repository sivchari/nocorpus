package main

import (
	"golang.org/x/tools/go/analysis/unitchecker"

	"github.com/sivchari/nocorpus"
)

func main() { unitchecker.Main(nocorpus.Analyzer) }
