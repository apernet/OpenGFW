package utils

func ByteSlicesToStrings(bss [][]byte) []string {
	ss := make([]string, len(bss))
	for i, bs := range bss {
		ss[i] = string(bs)
	}
	return ss
}
