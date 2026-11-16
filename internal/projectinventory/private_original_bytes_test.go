package projectinventory

import (
	"bytes"
	"testing"
)

func TestBunOriginalCaptureBudgetAndCopy(t *testing.T) {
	c := collector{}
	input := []byte("original")
	c.retainOriginal(1, input)
	input[0] = 'X'
	if string(c.result.OriginalInputs[0].Bytes) != "original" {
		t.Fatal("capture aliases read buffer")
	}
	frozen := PrivateOriginal(c.result)
	c.result.OriginalInputs[0].Bytes[0] = 'Y'
	if string(frozen.OriginalInputs[0].Bytes) != "original" {
		t.Fatal("private snapshot aliases originals")
	}
	c.retainOriginal(2, bytes.Repeat([]byte("x"), maxOriginalInputBytes))
	if !c.originalOverflow || len(c.result.OriginalInputs) != 0 {
		t.Fatal("overflow retained a partial authority witness")
	}
	c.retainOriginal(3, []byte("later"))
	if len(c.result.OriginalInputs) != 0 {
		t.Fatal("capture budget renewed")
	}
	rows := collector{}
	for i := 0; i < maxOriginalInputRows; i++ {
		rows.retainOriginal(uint32(i+1), []byte("x"))
	}
	if len(rows.result.OriginalInputs) != maxOriginalInputRows {
		t.Fatal("row boundary")
	}
	rows.retainOriginal(maxOriginalInputRows+1, []byte("x"))
	if !rows.originalOverflow || len(rows.result.OriginalInputs) != 0 {
		t.Fatal("row overflow retained prefix")
	}
}
