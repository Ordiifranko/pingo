package logger

// Wrapper over Golang log module.

import (
	"io"
	"log"
)

var (
	Debug *log.Logger

	// Enable Verbose logging.
	LogVerbose bool
)

func SetVerbose(verbose bool) {
	LogVerbose = verbose
}

// InitiLogger initializes the debug logger.
func InitLogger(DebugWriter io.Writer, InfoWriter io.Writer) {
	Debug = log.New(DebugWriter, "DEBUG: ", log.Ldate|log.Ltime)
}

// Debugf executes Debug.Printf, and passes format string and its arg.
func Debugf(fmt string, args ...interface{}) {
	if LogVerbose {
		Debug.Printf(fmt, args...)
	}
}

func Debugln(args ...interface{}) {
	if LogVerbose {
		Debug.Println(args...)
	}
}
