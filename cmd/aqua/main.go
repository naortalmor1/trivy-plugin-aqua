package main

import (
	"fmt"
	"log"
	"os"
	"sort"

	"strings"

	"github.com/urfave/cli/v2"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/buildClient"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/processor"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/scanner"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/uploader"
	"github.com/aquasecurity/trivy/pkg/commands"
	tlog "github.com/aquasecurity/trivy/pkg/log"
)

var (
	severities       string
	debug            bool
	skipResultUpload bool
	tags             map[string]string
)

func main() {
	app := cli.NewApp()
	app.Name = "aqua"
	app.Version = "0.0.1"
	app.ArgsUsage = "target"
	app.Usage = "Scan a filesystem location for vulnerabilities and config misconfiguration"
	app.EnableBashCompletion = true

	configCmd := commands.NewConfigCommand()
	configCmd.Action = func(context *cli.Context) error {
		if err := tlog.InitLogger(debug, false); err != nil {
			return err
		}

		if err := verifySeverities(); err != nil {
			return err
		}

		scanPath, _ := os.Getwd()
		if context.NArg() > 0 {
			// when scan path provided, use that
			scanPath = context.Args().First()
		}
		tlog.Logger.Debugf("Using scanPath %s", scanPath)

		client, err := buildClient.Get(scanPath)
		if err != nil {
			return err
		}

		results, err := scanner.Scan(context, scanPath)
		if err != nil {
			return err
		}

		processedResults := processor.ProcessResults(client, results)
		if err != nil {
			return err
		}

		if !skipResultUpload {
			if err := uploader.Upload(client, processedResults, tags); err != nil {
				return err
			}
		}

		return checkPolicyResults(processedResults)
	}
	configCmd.Flags = append(configCmd.Flags,
		&cli.StringFlag{
			Name:    "skip-result-upload",
			Aliases: []string{"s"},
			Usage:   "Add this flag if you want test failed policy locally before sending PR",
			EnvVars: []string{"TRIVY_SKIP_RESULT_UPLOAD"},
		},
		// Add any flags you want here
	)

	app.Commands = []*cli.Command{
		configCmd,
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func verifySeverities() error {

	if severities != "" {
		severities = strings.ToUpper(severities)
		sevList := strings.Split(severities, ",")
		for _, sev := range sevList {
			if !scanner.AllSeverities.Any(sev) {
				return fmt.Errorf("could not resolve the provided severity: %s\nOptions are: [%s]\n", sev, strings.Join(scanner.AllSeverities, ", "))
			}
		}
	}
	return nil
}

func checkPolicyResults(results []*buildsecurity.Result) error {
	uniqCount := 0

	var warns []string
	var failures []string

	for _, result := range results {
		for _, policyResult := range result.PolicyResults {
			if !policyResult.Failed {
				continue
			}

			if policyResult.Enforced {
				for _, reason := range strings.Split(policyResult.Reason, "\n") {
					if reason == "" {
						continue
					}
					uniqCount += 1
					failures = append(failures, reason)
				}
			} else {
				for _, reason := range strings.Split(policyResult.Reason, "\n") {
					if reason == "" {
						continue
					}
					warns = append(warns, reason)
				}
			}
		}
	}

	if len(warns) > 0 {
		sort.Strings(warns)
		_, _ = fmt.Fprintf(os.Stderr, "\n\x1b[33mAqua Assurance Policy warnings were triggered by the following checks failing:\n\n\x1b[0m")
		for _, warn := range warns {
			_, _ = fmt.Fprintf(os.Stderr, "\t- %s\n", warn)
		}
		_, _ = fmt.Fprintf(os.Stderr, "\n")
	}

	if len(failures) > 0 {
		sort.Strings(failures)
		_, _ = fmt.Fprintf(os.Stderr, "\n\x1b[31mAqua Assurance Policy build failed with the following checks failing:\n\n\x1b[0m")
		for _, failure := range failures {
			_, _ = fmt.Fprintf(os.Stderr, "\t- %s\n", failure)
		}
		_, _ = fmt.Fprintf(os.Stderr, "\n")
	}

	if uniqCount == 0 {
		return nil
	}

	return fmt.Errorf("\x1b[31m%d enforced policy control failure(s).\n\n\x1b[0m", len(failures))
}
