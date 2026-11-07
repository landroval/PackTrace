//go:build !linux || (!amd64 && !arm64)

package nativefs

func publicationPlanAvailable() error { return ErrUnavailable }

func publicationPlanBinding(*Publication) (string, error) { return "", ErrUnavailable }
func publicationPlanSources(*Publication) error           { return ErrUnavailable }
