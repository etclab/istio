package kceval

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"istio.io/istio/pkg/log"
)

// what should the filename be here?
type MLogWriter struct {
	filename string
	lock     sync.Mutex
}

const DEFAULT_FILENAME = "/var/run/eval-data/log.csv"

func NewMLogWriter(filename string) *MLogWriter {
	defaultFilepath := DEFAULT_FILENAME

	if filename != "" {
		defaultFilepath = filename
	}

	permissions := os.FileMode(0755)
	err := os.MkdirAll(filepath.Dir(defaultFilepath), permissions)
	if err != nil {
		log.Errorf("[dev] error creating directories: %v\n", err)
		return nil
	}

	// create the file if it does not exist
	_, err = os.Stat(defaultFilepath)
	if os.IsNotExist(err) {
		file, err := os.Create(defaultFilepath)
		if err != nil {
			log.Errorf("[dev] failed to create log file %s: %v", defaultFilepath, err)
		} else {
			file.Close()
		}
	}

	return &MLogWriter{
		filename: defaultFilepath,
	}
}

// entry can be:
// <event-type>,<user-id>,<timestamp>
// event-type: REGISTER, READY
func (mlw *MLogWriter) Append(entry string) error {
	mlw.lock.Lock()
	defer mlw.lock.Unlock()

	file, err := os.OpenFile(mlw.filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	_, err = file.WriteString(entry + "\n")
	if err != nil {
		return fmt.Errorf("failed to write to file: %v", err)
	}

	return nil
}
