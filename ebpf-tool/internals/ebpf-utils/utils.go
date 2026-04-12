// Package ebpfutils contains helper functions for interfacing c types with go's
package ebpfutils

func Int8ToString(array []int8) string {
	maxLength := len(array)
	result := make([]byte, 0, maxLength)
	for _, caracter := range array {
		if caracter == 0 {
			break
		}
		result = append(result, byte(caracter))
	}
	return string(result)
}
