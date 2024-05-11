package custom

func Concat(pieces ...[]byte) []byte {

	var combinedBytes []byte
	for _, data := range pieces {
		combinedBytes = append(combinedBytes, data...)
	}
	return combinedBytes
}
