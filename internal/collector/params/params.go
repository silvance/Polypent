// Package params is a tiny helper for reading typed values out of a
// collector's job.Parameters map without each collector reinventing
// the same type-switches.
package params

// Int returns m[k] coerced to int, falling back to def. JSON-decoded
// maps deliver numbers as float64; we accept int / int64 / float64 to
// keep the call sites quiet.
func Int(m map[string]any, k string, def int) int {
	if m == nil {
		return def
	}
	switch v := m[k].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return def
}

// Bool returns m[k] as bool, falling back to def.
func Bool(m map[string]any, k string, def bool) bool {
	if m == nil {
		return def
	}
	if b, ok := m[k].(bool); ok {
		return b
	}
	return def
}

// String returns m[k] as string, falling back to def.
func String(m map[string]any, k, def string) string {
	if m == nil {
		return def
	}
	if s, ok := m[k].(string); ok {
		return s
	}
	return def
}
