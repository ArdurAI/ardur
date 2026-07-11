// auditbench-score seals, verifies, and scores independently labeled studies.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ArdurAI/ardur/go/benchmark/independent"
)

type studyPaths struct {
	root          string
	corpus        string
	protocol      string
	prereg        string
	gold          string
	annotations   string
	adjudications string
	splits        string
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "seal":
		err = runSeal(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "score":
		err = runScore(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "auditbench-score: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: auditbench-score <seal|verify|score> [flags]")
	os.Exit(2)
}

func addStudyFlags(fs *flag.FlagSet) (*studyPaths, *string) {
	paths := &studyPaths{}
	fs.StringVar(&paths.root, "root", "", "study root")
	fs.StringVar(&paths.corpus, "corpus", "", "normalized corpus directory")
	fs.StringVar(&paths.protocol, "protocol", "", "preregistered protocol file")
	fs.StringVar(&paths.prereg, "prereg", "", "preregistration JSON")
	fs.StringVar(&paths.gold, "gold", "", "gold set JSON")
	fs.StringVar(&paths.annotations, "annotations", "", "annotation array JSON")
	fs.StringVar(&paths.adjudications, "adjudications", "", "adjudication array JSON, use [] when empty")
	fs.StringVar(&paths.splits, "splits", "", "split manifest JSON")
	sealPath := fs.String("seal", "", "seal JSON")
	return paths, sealPath
}

func (paths studyPaths) validate() error {
	if paths.root == "" || paths.corpus == "" || paths.protocol == "" || paths.prereg == "" || paths.gold == "" || paths.annotations == "" || paths.adjudications == "" || paths.splits == "" {
		return fmt.Errorf("root, corpus, protocol, prereg, gold, annotations, adjudications, and splits are required")
	}
	return nil
}

func runSeal(args []string) error {
	fs := flag.NewFlagSet("seal", flag.ContinueOnError)
	paths, sealPath := addStudyFlags(fs)
	sealedAt := fs.String("sealed-at", "", "explicit RFC3339 seal time")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := paths.validate(); err != nil {
		return err
	}
	if *sealPath == "" || *sealedAt == "" || fs.NArg() != 0 {
		return fmt.Errorf("seal output and sealed-at are required")
	}
	seal, err := independent.BuildSeal(paths.root, paths.corpus, paths.protocol, paths.prereg, paths.gold, paths.annotations, paths.adjudications, paths.splits, *sealedAt)
	if err != nil {
		return err
	}
	if err := independent.WriteArtifact(*sealPath, seal); err != nil {
		return err
	}
	digest, err := independent.SealDigest(seal)
	if err != nil {
		return err
	}
	fmt.Printf("sealed study %s (%s)\n", seal.StudyID, digest)
	return nil
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	paths, sealPath := addStudyFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := paths.validate(); err != nil {
		return err
	}
	if *sealPath == "" || fs.NArg() != 0 {
		return fmt.Errorf("seal is required")
	}
	var seal independent.Seal
	if err := independent.ReadStrictJSON(*sealPath, &seal); err != nil {
		return err
	}
	if err := independent.VerifySeal(paths.root, paths.corpus, paths.protocol, paths.prereg, paths.gold, paths.annotations, paths.adjudications, paths.splits, seal); err != nil {
		return err
	}
	fmt.Printf("verified study %s (%s)\n", seal.StudyID, seal.RootSHA256)
	return nil
}

func runScore(args []string) error {
	fs := flag.NewFlagSet("score", flag.ContinueOnError)
	paths, sealPath := addStudyFlags(fs)
	resultPath := fs.String("result", "", "SUT result JSON")
	split := fs.String("split", independent.SplitHeldOut, "development or held_out")
	output := fs.String("out", "", "score report output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := paths.validate(); err != nil {
		return err
	}
	if *sealPath == "" || *resultPath == "" || *output == "" || fs.NArg() != 0 {
		return fmt.Errorf("seal, result, and out are required")
	}
	var prereg independent.Preregistration
	var gold independent.GoldSet
	var splits independent.SplitManifest
	var seal independent.Seal
	var result independent.SUTResult
	for _, item := range []struct {
		path string
		dst  any
	}{{paths.prereg, &prereg}, {paths.gold, &gold}, {paths.splits, &splits}, {*sealPath, &seal}, {*resultPath, &result}} {
		if err := independent.ReadStrictJSON(item.path, item.dst); err != nil {
			return fmt.Errorf("read %s: %w", item.path, err)
		}
	}
	if err := independent.VerifySeal(paths.root, paths.corpus, paths.protocol, paths.prereg, paths.gold, paths.annotations, paths.adjudications, paths.splits, seal); err != nil {
		return err
	}
	report, err := independent.Score(prereg, seal, gold, splits, result, *split)
	if err != nil {
		return err
	}
	if err := independent.WriteArtifact(*output, report); err != nil {
		return err
	}
	fmt.Printf("scored %s on %s: %d/%d correct\n", report.SUTID, report.Split, report.Correct, report.Scenarios)
	return nil
}
