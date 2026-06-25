// Copyright 2026 Thomson Reuters
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stamp

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/thomsonreuters/stamp/pkg/config"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/logger"
	"github.com/thomsonreuters/stamp/pkg/output"
	"github.com/thomsonreuters/stamp/pkg/types"
	"github.com/thomsonreuters/stamp/pkg/validation"
	plugincobra "github.com/thomsonreuters/stamp/plugins/cobra"
)

var (
	version    = "dev"
	rootConfig config.ConfigurationIface
	rootLogger logger.Logger
	rootOutput output.OutputIface
)

var rootCmd = &cobra.Command{
	Use:   "stamp",
	Short: "A streamlined attestation framework for generating signed in-toto attestations",
	Long: `STAMP is a framework for generating, signing, and uploading attestations
to transparency logs. It provides a streamlined, extensible system with proper
in-toto attestation format support.

Configuration Precedence:
  CLI flags > Environment variables > Config file > Defaults`,
	Version: version,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := initConfig(cmd); err != nil {
			return err
		}

		if err := validation.ValidateCommandConstraints(cmd, rootConfig); err != nil {
			return err
		}

		if err := initLogger(); err != nil {
			return err
		}

		if err := initOutput(); err != nil {
			return err
		}

		return nil
	},
	SilenceErrors: true,
	SilenceUsage:  true,
}

func init() {
	_ = plugincobra.ApplyFlagGroup(rootCmd, flags.GlobalFlags)
	_ = plugincobra.ApplyFlagGroup(rootCmd, flags.SecurityFlags)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		out := rootOutput
		if out == nil {
			out = createErrorOutput()
		}
		handleError(out, err)
		os.Exit(pkgerrors.GetExitCode(err))
	}
}

func initConfig(cmd *cobra.Command) error {
	v := viper.New()

	cfgFile := cmd.Flag("config").Value.String()

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err == nil {
			v.AddConfigPath(home)
			v.SetConfigName(".stamp")
			v.SetConfigType("yaml")
		}
	}

	v.SetEnvPrefix("STAMP")
	v.AutomaticEnv()

	if err := bindFlagsToViper(v, cmd.Flags()); err != nil {
		return fmt.Errorf("failed to bind flags: %w", err)
	}
	if err := bindFlagsToViper(v, cmd.PersistentFlags()); err != nil {
		return fmt.Errorf("failed to bind persistent flags: %w", err)
	}

	if err := v.ReadInConfig(); err != nil {
		if cfgFile != "" {
			return fmt.Errorf("failed to read config file: %w", err)
		}
	}

	rootConfig = config.NewConfiguration(v)

	return nil
}

func bindFlagsToViper(v *viper.Viper, flagSet *pflag.FlagSet) error {
	var bindErr error
	flagSet.VisitAll(func(flag *pflag.Flag) {
		if bindErr != nil {
			return
		}

		configPaths, ok := flag.Annotations[plugincobra.AnnotationConfigPath]
		if !ok || len(configPaths) == 0 {
			return
		}

		configPath := configPaths[0]
		if configPath == "" || configPath == plugincobra.NoConfig {
			return
		}

		if err := v.BindPFlag(configPath, flag); err != nil {
			bindErr = fmt.Errorf("binding flag %q to %q: %w", flag.Name, configPath, err)
			return
		}

		if envVars, hasEnvVar := flag.Annotations[plugincobra.AnnotationEnvironmentVariable]; hasEnvVar && len(envVars) > 0 {
			_ = v.BindEnv(configPath, envVars[0])
		}
	})
	return bindErr
}

func initLogger() error {
	logLevel := rootConfig.GetString(flags.LogLevel)
	logFormat := rootConfig.GetString(flags.LogFormat)
	logFile := rootConfig.GetString(flags.LogFile)
	quiet := rootConfig.GetBool(flags.Quiet)
	debug := rootConfig.GetBool(flags.Debug)

	if debug {
		logLevel = types.LogLevelDebug.String()
	}

	writer := determineLogWriter(logFile, quiet)

	rootLogger = logger.New(&logger.Config{
		Level:     types.LogLevel(logLevel),
		Format:    toLoggerFormat(logFormat),
		Writer:    writer,
		AddSource: debug,
	})
	return nil
}

func toLoggerFormat(cliFormat string) types.LogFormat {
	switch cliFormat {
	case "json":
		return types.LogFormatJSON
	default:
		return types.LogFormatConsole
	}
}

func determineLogWriter(logFile string, quiet bool) io.Writer {
	if logFile != "" {
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			if quiet {
				return io.Discard
			}
			return os.Stderr
		}
		return file
	}

	if quiet {
		return io.Discard
	}

	return os.Stderr
}

func initOutput() error {
	logOnly := rootConfig.GetBool(flags.LogOnly)
	quiet := rootConfig.GetBool(flags.Quiet)
	debug := rootConfig.GetBool(flags.Debug)
	noColor := rootConfig.GetBool(flags.NoColor) || os.Getenv("NO_COLOR") != ""
	format := rootConfig.GetString(flags.LogFormat)

	rootOutput = output.New(
		output.WithLogOnly(logOnly),
		output.WithQuiet(quiet),
		output.WithDebug(debug),
		output.WithNoColor(noColor),
		output.WithFormat(format),
	)

	return nil
}

func createErrorOutput() output.OutputIface {
	return output.New(
		output.WithQuiet(false),
		output.WithLogOnly(false),
		output.WithDebug(false),
		output.WithNoColor(false),
		output.WithFormat("console"),
	)
}

func handleError(out output.OutputIface, err error) {
	if err == nil {
		return
	}

	{
		var e *pkgerrors.BaseError
		var e1 *pkgerrors.ValidationError
		switch {
		case errors.As(err, &e):
			displayBaseError(out, e)
		case errors.As(err, &e1):
			displayValidationError(out, e1)
		default:
			displayUnhandledError(out, err)
		}
	}
}

func displayBaseError(out output.OutputIface, e *pkgerrors.BaseError) {
	out.Error("%s Error: %s", errorIcon(out), e.Message)

	if ctx := buildContext(e.Component, e.Operation); ctx != "" {
		out.Error("  Context: %s", ctx)
	}

	if e.Cause != nil {
		out.Error("  Cause: %s", e.Cause.Error())
	}

	displaySuggestions(out, e.Suggestions)
}

func displayValidationError(out output.OutputIface, v *pkgerrors.ValidationError) {
	out.Error("%s Validation failed:", errorIcon(out))

	for field, errs := range v.Fields {
		for _, msg := range errs {
			out.Error("  • %s: %s", field, msg)
		}
	}

	displaySuggestions(out, v.Suggestions)
}

func displayUnhandledError(out output.OutputIface, err error) {
	out.Error("%s Error: %v", errorIcon(out), err)
}

func displaySuggestions(out output.OutputIface, suggestions []string) {
	if len(suggestions) == 0 {
		return
	}

	out.Error("  Suggestions:")
	for _, s := range suggestions {
		out.Error("    • %s", s)
	}
}

func errorIcon(out output.OutputIface) string {
	if out.IsNoColor() {
		return "✗"
	}
	return string(output.ColorRed) + "✗" + string(output.ColorReset)
}

func buildContext(component, operation string) string {
	parts := []string{}
	if component != "" {
		parts = append(parts, component)
	}
	if operation != "" {
		parts = append(parts, operation)
	}
	return strings.Join(parts, "/")
}
