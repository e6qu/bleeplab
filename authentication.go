package bleeplab

import "crypto/subtle"

func tokenMatches(expected, presented string) bool {
	if expected == "" || len(expected) != len(presented) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(presented)) == 1
}
