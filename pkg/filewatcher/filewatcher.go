package filewatcher

import (
	"bufio"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
)

type Options struct {
	Interval time.Duration
	File     string
}

type FileWatcher struct {
	Options Options
	watcher *time.Ticker
}

func New(options Options) (*FileWatcher, error) {
	return &FileWatcher{Options: options}, nil
}

func (f *FileWatcher) Watch() (chan string, error) {
	tickWatcher := time.NewTicker(f.Options.Interval)
	f.watcher = tickWatcher
	out := make(chan string)
	if !fileutil.FileExists(f.Options.File) {
		return nil, errors.New("file doesn't exist")
	}
	go func() {
		var seenLines sync.Map
		for range f.watcher.C {
			r, err := os.Open(f.Options.File)
			if err != nil {
				gologger.Fatal().Msgf("Couldn't monitor file: %s", err)
				return
			}
			sc := bufio.NewScanner(r)
			for sc.Scan() {
				data := sc.Text()
				_, loaded := seenLines.LoadOrStore(data, struct{}{})
				if !loaded {
					out <- data
				}

			}
			r.Close()
		}
	}()
	return out, nil
}

func (f *FileWatcher) Close() {
	f.watcher.Stop()
}
