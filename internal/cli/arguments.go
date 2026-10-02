package cli

import "strings"

// ArgumentAction is a requested action, not execution or scan completion.
type ArgumentAction uint8

const (
	ArgumentActionUnknown ArgumentAction = iota
	ArgumentActionScan
	ArgumentActionHelp
	ArgumentActionScanHelp
	ArgumentActionVersion
)

// ArgumentChecks is requested category membership, not qualified coverage.
type ArgumentChecks uint8

const (
	ArgumentCheckMalicious ArgumentChecks = 1 << iota
	ArgumentCheckVulnerability
	ArgumentCheckIntegrity
)

// ArgumentOptions records explicit options, including default-valued ones.
type ArgumentOptions uint16

const (
	ArgumentOptionManager ArgumentOptions = 1 << iota
	ArgumentOptionChecks
	ArgumentOptionFailOn
	ArgumentOptionFormat
	ArgumentOptionPrivacy
	ArgumentOptionPolicy
	ArgumentOptionStateDir
	ArgumentOptionOutput
)

// ScanArgumentRequest is unvalidated policy/path/output request data.
// Empty StateDir defers default resolution; no field establishes native safety.
type ScanArgumentRequest struct {
	Path, Manager, Format, Privacy, PolicyPath, StateDir, Output string
	Checks, FailOn                                               ArgumentChecks
	Provided                                                     ArgumentOptions
}

// Invocation never authorizes executing or displaying the requested action.
type Invocation struct {
	Action ArgumentAction
	Scan   ScanArgumentRequest
}

type ArgumentErrorCode uint8

const (
	ArgumentErrorUnknown ArgumentErrorCode = iota
	ArgumentErrorMissingCommand
	ArgumentErrorCommandUnsupported
	ArgumentErrorControlArguments
	ArgumentErrorOptionUnsupported
	ArgumentErrorOptionRepeated
	ArgumentErrorOptionMissingValue
	ArgumentErrorOptionValueInvalid
	ArgumentErrorRootMissing
	ArgumentErrorRootInvalid
	ArgumentErrorExtraArgument
	ArgumentErrorEnforcementOutsideChecks
)

// ArgumentError carries only fixed classification and non-string locators.
type ArgumentError struct {
	Code     ArgumentErrorCode
	ArgIndex int
	Option   ArgumentOptions
}

func (e *ArgumentError) Error() string {
	switch e.Code {
	case ArgumentErrorMissingCommand:
		return "cli: missing-command"
	case ArgumentErrorCommandUnsupported:
		return "cli: unsupported-command"
	case ArgumentErrorControlArguments:
		return "cli: control-arguments"
	case ArgumentErrorOptionUnsupported:
		return "cli: unsupported-option"
	case ArgumentErrorOptionRepeated:
		return "cli: repeated-option"
	case ArgumentErrorOptionMissingValue:
		return "cli: missing-option-value"
	case ArgumentErrorOptionValueInvalid:
		return "cli: invalid-option-value"
	case ArgumentErrorRootMissing:
		return "cli: missing-root"
	case ArgumentErrorRootInvalid:
		return "cli: invalid-root"
	case ArgumentErrorExtraArgument:
		return "cli: extra-argument"
	case ArgumentErrorEnforcementOutsideChecks:
		return "cli: enforcement-outside-checks"
	default:
		return "cli: invalid-arguments"
	}
}

// ParseArgs parses argv excluding the program name without I/O or policy application.
// The caller must qualify effective policy, paths and destinations before execution.
func ParseArgs(args []string) (Invocation, error) {
	if len(args) == 0 {
		return argumentFailure(ArgumentErrorMissingCommand, -1, 0)
	}
	switch args[0] {
	case "--help", "--version":
		if len(args) != 1 {
			return argumentFailure(ArgumentErrorControlArguments, 1, 0)
		}
		action := ArgumentActionHelp
		if args[0] == "--version" {
			action = ArgumentActionVersion
		}
		return Invocation{Action: action}, nil
	case "scan":
		if len(args) > 1 && args[1] == "--help" {
			if len(args) != 2 {
				return argumentFailure(ArgumentErrorControlArguments, 2, 0)
			}
			return Invocation{Action: ArgumentActionScanHelp}, nil
		}
	default:
		return argumentFailure(ArgumentErrorCommandUnsupported, 0, 0)
	}

	request := ScanArgumentRequest{Manager: "auto", Checks: ArgumentCheckMalicious | ArgumentCheckVulnerability | ArgumentCheckIntegrity, Format: "terminal", Privacy: "portable", Output: "-"}
	failOnIndex := -1
	i := 1
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
		if option == 0 {
			return argumentFailure(ArgumentErrorOptionUnsupported, i, 0)
		}
		if request.Provided&option != 0 {
			return argumentFailure(ArgumentErrorOptionRepeated, i, option)
		}
		optionIndex, valueIndex := i, i
		if !attached {
			i++
			if i == len(args) || strings.HasPrefix(args[i], "--") {
				return argumentFailure(ArgumentErrorOptionMissingValue, optionIndex, option)
			}
			value, valueIndex = args[i], i
		}
		if !applyArgumentOption(&request, option, value) {
			return argumentFailure(ArgumentErrorOptionValueInvalid, valueIndex, option)
		}
		request.Provided |= option
		if option == ArgumentOptionFailOn {
			failOnIndex = optionIndex
		}
		i++
	}
	if i == len(args) {
		return argumentFailure(ArgumentErrorRootMissing, -1, 0)
	}
	if args[i] == "" || strings.IndexByte(args[i], 0) >= 0 {
		return argumentFailure(ArgumentErrorRootInvalid, i, 0)
	}
	if i+1 < len(args) {
		return argumentFailure(ArgumentErrorExtraArgument, i+1, 0)
	}
	request.Path = args[i]
	if request.FailOn&^request.Checks != 0 {
		return argumentFailure(ArgumentErrorEnforcementOutsideChecks, failOnIndex, ArgumentOptionFailOn)
	}
	return Invocation{Action: ArgumentActionScan, Scan: request}, nil
}

func argumentFailure(code ArgumentErrorCode, index int, option ArgumentOptions) (Invocation, error) {
	return Invocation{}, &ArgumentError{Code: code, ArgIndex: index, Option: option}
}

func argumentOption(name string) ArgumentOptions {
	switch name {
	case "--manager":
		return ArgumentOptionManager
	case "--checks":
		return ArgumentOptionChecks
	case "--fail-on":
		return ArgumentOptionFailOn
	case "--format":
		return ArgumentOptionFormat
	case "--privacy":
		return ArgumentOptionPrivacy
	case "--policy":
		return ArgumentOptionPolicy
	case "--state-dir":
		return ArgumentOptionStateDir
	case "--output":
		return ArgumentOptionOutput
	default:
		return 0
	}
}

func applyArgumentOption(request *ScanArgumentRequest, option ArgumentOptions, value string) bool {
	if value == "" || strings.IndexByte(value, 0) >= 0 {
		return false
	}
	switch option {
	case ArgumentOptionManager:
		switch value {
		case "auto", "npm", "bun", "npm@8.19.4", "npm@10.9.4", "npm@11.6.2", "bun@1.3.2", "bun@1.4.2":
			request.Manager = value
		default:
			return false
		}
	case ArgumentOptionChecks:
		set, ok := parseArgumentChecks(value, false)
		if !ok {
			return false
		}
		request.Checks = set
	case ArgumentOptionFailOn:
		set, ok := parseArgumentChecks(value, true)
		if !ok {
			return false
		}
		request.FailOn = set
	case ArgumentOptionFormat:
		switch value {
		case "terminal", "json", "sarif":
			request.Format = value
		default:
			return false
		}
	case ArgumentOptionPrivacy:
		switch value {
		case "portable", "local":
			request.Privacy = value
		default:
			return false
		}
	case ArgumentOptionPolicy:
		request.PolicyPath = value
	case ArgumentOptionStateDir:
		request.StateDir = value
	case ArgumentOptionOutput:
		request.Output = value
	default:
		return false
	}
	return true
}

func parseArgumentChecks(text string, allowNone bool) (ArgumentChecks, bool) {
	if allowNone && text == "none" {
		return 0, true
	}
	var set ArgumentChecks
	for {
		part, rest, more := strings.Cut(text, ",")
		var bit ArgumentChecks
		switch part {
		case "malicious":
			bit = ArgumentCheckMalicious
		case "vulnerability":
			bit = ArgumentCheckVulnerability
		case "integrity":
			bit = ArgumentCheckIntegrity
		default:
			return 0, false
		}
		if set&bit != 0 {
			return 0, false
		}
		set |= bit
		if !more {
			return set, true
		}
		text = rest
	}
}
