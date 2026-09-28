package utils

import "log"

// LogDebug logs details that are useful to diagnose a problem but must not be sent to the clients
func LogDebug(format string, args ...interface{}) {
	log.Printf("DBG "+format, args...)
}
