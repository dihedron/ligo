package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"runtime"
	"runtime/pprof"
	"strings"

	"github.com/dihedron/ligo/pkg/metadata"
)

var (
	cpuprof *os.File
	memprof *os.File
)

func init() {
	const LevelNone = slog.Level(1000)

	options := &slog.HandlerOptions{
		Level:     LevelNone,
		AddSource: true,
	}

	// load .env file if specified and present; it may set the variables below,
	// so it comes first, and is logged once the logger is configured
	dotenv, dotenvSet := os.LookupEnv(metadata.DotEnvVarName)
	var dotenvErr error
	if dotenvSet {
		dotenvErr = metadata.LoadDotEnv(dotenv)
	}

	// get log elevel from environment variable where, given
	// the binary name "my-app", the environment variable is "MY_APP_LOG_LEVEL"
	level, levelSet := os.LookupEnv(
		fmt.Sprintf(
			"%s_LOG_LEVEL",
			strings.ReplaceAll(
				strings.ToUpper(
					path.Base(os.Args[0]),
				),
				"-",
				"_",
			),
		),
	)
	if levelSet { // the values of --log-level (client.Globals), which reads the same variable
		switch strings.ToLower(level) {
		case "debug":
			options.Level = slog.LevelDebug
		case "info":
			options.Level = slog.LevelInfo
		case "warn":
			options.Level = slog.LevelWarn
		case "error":
			options.Level = slog.LevelError
		case "off":
			options.Level = LevelNone
		}
	}

	// get the name of the file to log to from environment variable where, given
	// the binary name "my-app", the environment variable is "MY_APP_LOG_STREAM"
	var writer io.Writer = os.Stderr
	stream, ok := os.LookupEnv(
		fmt.Sprintf(
			"%s_LOG_STREAM",
			strings.ReplaceAll(
				strings.ToUpper(
					path.Base(os.Args[0]),
				),
				"-",
				"_",
			),
		),
	)
	if ok {
		switch strings.ToLower(stream) {
		case "stderr", "error", "err", "e":
			writer = os.Stderr
		case "stdout", "output", "out", "o":
			writer = os.Stdout
		case "file":
			filename := fmt.Sprintf("%s-%d.log", path.Base(os.Args[0]), os.Getpid())
			var err error
			writer, err = os.Create(path.Clean(filename))
			if err != nil {
				writer = os.Stderr
			}
		}
	}

	// initialise the logger
	handler := slog.NewTextHandler(writer, options)
	slog.SetDefault(slog.New(handler))

	if dotenvSet {
		switch {
		case dotenvErr == nil:
			slog.Info("successfully loaded .env file", "path", dotenv)
		case levelSet:
			slog.Error("error loading .env file", "path", dotenv, "error", dotenvErr)
		default: // no level set means no logger, but a failed load must not go unseen
			fmt.Fprintf(os.Stderr, "error loading .env file %s: %v\n", dotenv, dotenvErr)
		}
	}

	// check if CPU profiling should be enabled
	filename, ok := os.LookupEnv(
		fmt.Sprintf(
			"%s_CPU_PROFILE",
			strings.ReplaceAll(
				strings.ToUpper(
					path.Base(os.Args[0]),
				),
				"-",
				"_",
			),
		),
	)
	if ok && filename != "" {
		f, err := os.Create(path.Clean(filename))
		if err != nil {
			slog.Error("could not create CPU profile", "error", err)
		}
		cpuprof = f
		if err := pprof.StartCPUProfile(f); err != nil {
			slog.Error("could not start CPU profile", "error", err)
		}
	}

	// check if CPU profiling should be enabled
	filename, ok = os.LookupEnv(
		fmt.Sprintf(
			"%s_MEM_PROFILE",
			strings.ReplaceAll(
				strings.ToUpper(
					path.Base(os.Args[0]),
				),
				"-",
				"_",
			),
		),
	)
	if ok && filename != "" {
		f, err := os.Create(path.Clean(filename))
		if err != nil {
			slog.Error("could not create memory profile", "error", err)
		}
		memprof = f
	}
}

func cleanup() {
	if cpuprof != nil {
		pprof.StopCPUProfile()
		closeProfile(cpuprof)
	}
	if memprof != nil {
		runtime.GC() // get up-to-date statistics
		if err := pprof.WriteHeapProfile(memprof); err != nil {
			slog.Error("could not write memory profile", "error", err)
		}
		closeProfile(memprof)
	}
}

// closeProfile closes a profile file, reporting a failure, which can lose
// the end of the profile.
func closeProfile(f *os.File) {
	if err := f.Close(); err != nil {
		slog.Error("could not close profile", "file", f.Name(), "error", err)
	}
}
