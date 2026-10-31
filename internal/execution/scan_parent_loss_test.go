//go:build linux

package execution

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestScanLostPrivateOutputCancelsNativeWork(t *testing.T) {
	reader, writer, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sender := scanSender{c: newChannel(nil, writer, &traffic{}), start: time.Now(), cancel: cancel}
	stop := sender.sampleLoop()
	defer stop()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("lost supervisor left native acquisition context running")
	}
}
