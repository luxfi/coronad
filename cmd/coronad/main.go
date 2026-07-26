// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command coronad is the offline Corona (Ringtail / Module-LWE) threshold-signer
// CLI. It orchestrates the corona kernel and emits warp.CoronaEvidence.
//
// Subcommands:
//
//	coronad version   print the build identity
//	coronad demo      run an in-process t-of-n committee: dealerless bootstrap,
//	                  threshold-sign a subject, and verify the emitted
//	                  CoronaEvidence with the warp Corona lane verifier.
//
// A production daemon (one node = one committee member over a real network
// transport wrapping corona/networking) is deliberately NOT built here; see the
// module's RED HANDOFF. The CLI exposes the in-process proof and version only.
package main

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/luxfi/coronad"
	"github.com/spf13/cobra"

	"github.com/luxfi/ids"
	"github.com/luxfi/warp"

	warppulsar "github.com/luxfi/warp/pulsar"
)

const version = "coronad v0.1.0 (corona Ringtail / Module-LWE offline threshold signer)"

func main() {
	root := &cobra.Command{
		Use:   "coronad",
		Short: "Offline Corona (Ringtail / Module-LWE) threshold-signer service",
	}
	root.AddCommand(versionCmd(), demoCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the coronad build identity",
		RunE: func(_ *cobra.Command, _ []string) error {
			fmt.Println(version)
			return nil
		},
	}
}

func demoCmd() *cobra.Command {
	var (
		n         int
		threshold int
	)
	cmd := &cobra.Command{
		Use:   "demo",
		Short: "Run an in-process committee: bootstrap -> sign -> warp-verify",
		RunE: func(_ *cobra.Command, _ []string) error {
			if threshold < 1 || threshold >= n || n < 2 {
				return fmt.Errorf("require 1 <= threshold < n and n >= 2 (got t=%d n=%d)", threshold, n)
			}
			validators := make([]string, n)
			for i := range validators {
				validators[i] = fmt.Sprintf("validator-%02d", i)
			}
			chainID := ids.ID{0xC0, 0x12, 0x20, 0x06}

			fmt.Printf("bootstrapping dealerless %d-of-%d Corona key era...\n", threshold, n)
			era, err := coronad.Bootstrap(chainID, 1, threshold, validators, rand.Reader)
			if err != nil {
				return fmt.Errorf("bootstrap: %w", err)
			}

			subject := make([]byte, 32)
			if _, err := rand.Read(subject); err != nil {
				return err
			}
			fmt.Printf("threshold-signing subject %x...\n", subject[:8])
			ev, err := coronad.NewSigner(era, coronad.Loopback).ThresholdSign(subject)
			if err != nil {
				return fmt.Errorf("sign: %w", err)
			}
			fmt.Printf("emitted CoronaEvidence: chain=%x keyEra=%d gen=%d sig=%d bytes\n",
				ev.ChainID[:4], ev.KeyEraID, ev.Generation, len(ev.Sig))

			resolver := coronad.NewEraResolver()
			resolver.Add(era)
			v := warppulsar.NewRingtailVerifier(resolver)
			if err := v.VerifyRingtailThreshold(subject, ev); err != nil {
				return fmt.Errorf("warp verify: %w", err)
			}
			fmt.Println("OK: warp/pulsar.RingtailVerifier ACCEPTED the CoronaEvidence")
			_ = warp.DefaultCoronaSuiteID
			return nil
		},
	}
	cmd.Flags().IntVar(&n, "n", 5, "committee size")
	cmd.Flags().IntVar(&threshold, "t", 3, "signing threshold")
	return cmd
}
