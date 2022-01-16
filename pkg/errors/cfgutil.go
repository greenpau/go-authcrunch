package errors

// Config parsing errors.
const (
	ErrValidateArgTooFew  StandardError = "too few arguments for %q directive (config: %d, min: %d)"
	ErrValidateArgTooMany StandardError = "too many args for %q directive (config: %d, max: %d)"
)
