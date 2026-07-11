// auditbench-label creates one-view annotation bundles and adjudicates
// independently authored annotation artifacts into a gold set.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ArdurAI/ardur/go/benchmark/independent"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "bundle":
		err = runBundle(os.Args[2:])
	case "adjudicate":
		err = runAdjudicate(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "auditbench-label: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: auditbench-label <bundle|adjudicate> [flags]")
	os.Exit(2)
}

func runBundle(args []string) error {
	fs := flag.NewFlagSet("bundle", flag.ContinueOnError)
	studyID := fs.String("study-id", "", "study identifier")
	view := fs.String("view", "", "oracle or evidence")
	source := fs.String("source", "", "normalized source artifact")
	output := fs.String("out", "", "label bundle output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *studyID == "" || *view == "" || *source == "" || *output == "" || fs.NArg() != 0 {
		return fmt.Errorf("usage: auditbench-label bundle -study-id ID -view oracle|evidence -source FILE -out FILE")
	}
	bundle, err := independent.BuildLabelBundle(*studyID, *view, *source)
	if err != nil {
		return err
	}
	if err := independent.WriteArtifact(*output, bundle); err != nil {
		return err
	}
	hash, err := independent.ArtifactDigest(bundle)
	if err != nil {
		return err
	}
	fmt.Printf("wrote %s bundle for %s (%s)\n", bundle.View, bundle.ScenarioID, hash)
	return nil
}

func runAdjudicate(args []string) error {
	fs := flag.NewFlagSet("adjudicate", flag.ContinueOnError)
	studyID := fs.String("study-id", "", "study identifier")
	minimum := fs.Int("minimum-annotators", 2, "minimum independent annotators per view")
	annotationsPath := fs.String("annotations", "", "JSON array of annotations")
	decisionsPath := fs.String("decisions", "", "optional JSON array of adjudications")
	output := fs.String("out", "", "gold set output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *studyID == "" || *annotationsPath == "" || *output == "" || fs.NArg() != 0 {
		return fmt.Errorf("usage: auditbench-label adjudicate -study-id ID -annotations FILE [-decisions FILE] -out FILE")
	}
	var annotations []independent.Annotation
	if err := independent.ReadStrictJSON(*annotationsPath, &annotations); err != nil {
		return fmt.Errorf("read annotations: %w", err)
	}
	var decisions []independent.Adjudication
	if *decisionsPath != "" {
		if err := independent.ReadStrictJSON(*decisionsPath, &decisions); err != nil {
			return fmt.Errorf("read adjudications: %w", err)
		}
	}
	gold, err := independent.Adjudicate(*studyID, *minimum, annotations, decisions)
	if err != nil {
		return err
	}
	if err := independent.WriteArtifact(*output, gold); err != nil {
		return err
	}
	fmt.Printf("wrote gold set for %d scenarios\n", len(gold.Records))
	return nil
}
