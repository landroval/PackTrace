package cli

import "strings"

// Setup explicitly designates a user policy once. It never discovers target config.
type SetupArgumentRequest struct {
	PolicyPath, StateDir, Privacy, TrustedSnapshotDigest string
}

func parseSetupArgs(args []string) (Invocation, error) {
	if len(args) > 1 && args[1] == "--help" {
		if len(args) != 2 {
			return argumentFailure(ArgumentErrorControlArguments, 2, 0)
		}
		return Invocation{Action: ArgumentActionSetupHelp}, nil
	}
	r := ScanArgumentRequest{Privacy: "local"}
	for i := 1; i < len(args); i++ {
		name, value, attached := strings.Cut(args[i], "=")
		option := argumentOption(name)
		if option != ArgumentOptionPolicy && option != ArgumentOptionStateDir && option != ArgumentOptionPrivacy && option != ArgumentOptionTrustedSnapshotDigest {
			return argumentFailure(ArgumentErrorOptionUnsupported, i, 0)
		}
		if r.Provided&option != 0 {
			return argumentFailure(ArgumentErrorOptionRepeated, i, option)
		}
		if !attached {
			i++
			if i == len(args) || strings.HasPrefix(args[i], "--") {
				return argumentFailure(ArgumentErrorOptionMissingValue, i-1, option)
			}
			value = args[i]
		}
		if !applyArgumentOption(&r, option, value) {
			return argumentFailure(ArgumentErrorOptionValueInvalid, i, option)
		}
		r.Provided |= option
	}
	return Invocation{Action: ArgumentActionSetup, Setup: SetupArgumentRequest{PolicyPath: r.PolicyPath, StateDir: r.StateDir, Privacy: r.Privacy, TrustedSnapshotDigest: r.TrustedSnapshotDigest}}, nil
}
