package cli

import (
	"encoding/hex"
	"packtrace/internal/intel"
	"strings"
)

// All fields are requests, not native/state/network/output authority. Empty
// StateDir defers cache-root resolution to the controller, never this parser.
func canonicalSnapshotDigest(value string) bool {
	_, e := intel.ParseSnapshotDigest(value)
	return e == nil
}

type IntelArgumentRequest struct {
	Action                                                                           ArgumentAction
	StateDir, Input, Output, TrustedSnapshotDigest, Generation, ApplyPreview, Format string
	Full                                                                             bool
	Provided                                                                         ArgumentOptions
}

func parseIntelArgs(args []string) (Invocation, error) {
	if len(args) < 2 {
		return argumentFailure(ArgumentErrorMissingCommand, -1, 0)
	}
	request := IntelArgumentRequest{Format: "terminal"}
	action := ArgumentActionUnknown
	if args[0] == "cache" {
		if args[1] == "prune" {
			action = ArgumentActionCachePrune
		}
	} else {
		switch args[1] {
		case "sync":
			action = ArgumentActionIntelSync
		case "import":
			action = ArgumentActionIntelImport
		case "export":
			action = ArgumentActionIntelExport
		case "status":
			action = ArgumentActionIntelStatus
		case "pin":
			action = ArgumentActionIntelPin
		case "unpin":
			action = ArgumentActionIntelUnpin
		}
	}
	if action == ArgumentActionUnknown {
		return argumentFailure(ArgumentErrorCommandUnsupported, 1, 0)
	}
	request.Action = action
	allowed := ArgumentOptionStateDir
	if action != ArgumentActionIntelPin && action != ArgumentActionIntelUnpin {
		allowed |= ArgumentOptionFormat | ArgumentOptionInteractive
	}
	switch action {
	case ArgumentActionIntelSync:
		allowed |= ArgumentOptionFull
	case ArgumentActionIntelImport:
		allowed |= ArgumentOptionTrustedSnapshotDigest
	case ArgumentActionIntelExport:
		allowed |= ArgumentOptionOutput
	case ArgumentActionCachePrune:
		allowed |= ArgumentOptionApplyPreview
	}
	i := 2
	for i < len(args) {
		token := args[i]
		if token == "--" {
			i++
			break
		}
		if !strings.HasPrefix(token, "-") || token == "-" {
			break
		}
		name, value, attached := strings.Cut(token, "=")
		option := argumentOption(name)
		switch name {
		case "--trusted-snapshot-digest":
			option = ArgumentOptionTrustedSnapshotDigest
		case "--apply":
			option = ArgumentOptionApplyPreview
		case "--full":
			option = ArgumentOptionFull
		}
		if option == 0 || option&allowed == 0 {
			return argumentFailure(ArgumentErrorOptionUnsupported, i, option)
		}
		if request.Provided&option != 0 {
			return argumentFailure(ArgumentErrorOptionRepeated, i, option)
		}
		request.Provided |= option
		if option == ArgumentOptionInteractive {
			if attached {
				return argumentFailure(ArgumentErrorOptionValueInvalid, i, option)
			}
			i++
			continue
		}
		if option == ArgumentOptionFull {
			if attached {
				return argumentFailure(ArgumentErrorOptionValueInvalid, i, option)
			}
			request.Full = true
			i++
			continue
		}
		at := i
		if !attached {
			i++
			if i == len(args) || strings.HasPrefix(args[i], "--") {
				return argumentFailure(ArgumentErrorOptionMissingValue, at, option)
			}
			value = args[i]
		}
		if value == "" || strings.IndexByte(value, 0) >= 0 {
			return argumentFailure(ArgumentErrorOptionValueInvalid, i, option)
		}
		switch option {
		case ArgumentOptionStateDir:
			request.StateDir = value
		case ArgumentOptionOutput:
			if value == "-" {
				return argumentFailure(ArgumentErrorOptionValueInvalid, i, option)
			}
			request.Output = value
		case ArgumentOptionFormat:
			if value != "terminal" && value != "json" {
				return argumentFailure(ArgumentErrorOptionValueInvalid, i, option)
			}
			request.Format = value
		case ArgumentOptionTrustedSnapshotDigest:
			if !canonicalSnapshotDigest(value) {
				return argumentFailure(ArgumentErrorOptionValueInvalid, i, option)
			}
			request.TrustedSnapshotDigest = value
		case ArgumentOptionApplyPreview:
			if !intelArgumentID(value) {
				return argumentFailure(ArgumentErrorOptionValueInvalid, i, option)
			}
			request.ApplyPreview = value
		}
		i++
	}
	wantOperand := action == ArgumentActionIntelImport || action == ArgumentActionIntelPin || action == ArgumentActionIntelUnpin
	if wantOperand {
		if i == len(args) {
			return argumentFailure(ArgumentErrorRootMissing, -1, 0)
		}
		value := args[i]
		if value == "" || strings.IndexByte(value, 0) >= 0 {
			return argumentFailure(ArgumentErrorRootInvalid, i, 0)
		}
		if action == ArgumentActionIntelImport {
			request.Input = value
		} else {
			if !intelArgumentID(value) {
				return argumentFailure(ArgumentErrorRootInvalid, i, 0)
			}
			request.Generation = value
		}
		i++
	}
	if i != len(args) {
		return argumentFailure(ArgumentErrorExtraArgument, i, 0)
	}
	if action == ArgumentActionIntelExport && request.Output == "" {
		return argumentFailure(ArgumentErrorOptionMissingValue, -1, ArgumentOptionOutput)
	}
	if request.Provided&ArgumentOptionInteractive != 0 {
		if request.Format != "terminal" {
			return argumentFailure(ArgumentErrorOptionValueInvalid, -1, ArgumentOptionInteractive)
		}
		request.Format = "terminal-interactive"
	}
	return Invocation{Action: action, Intel: request}, nil
}
func intelArgumentID(value string) bool {
	raw, e := hex.DecodeString(value)
	return e == nil && len(raw) == 32 && hex.EncodeToString(raw) == value && value != strings.Repeat("0", 64)
}
