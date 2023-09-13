package utils

import (
	"fmt"
	"os"
	"path"
	"strings"
)

func FilenameWithoutExtension(fn string) string {
	return strings.TrimSuffix(fn, path.Ext(fn))
}

func PathFromFilenameWithoutExtension(fn string) string {
	s := strings.TrimSuffix(fn, path.Ext(fn))
	return fmt.Sprintf("/%s", s)
}

func TitleFromFilename(fn string) string {
	return strings.ToTitle(FilenameWithoutExtension(fn))
}

func EnvToMap() (map[string]string, error) {
	envMap := make(map[string]string)
	var err error

	for _, v := range os.Environ() {
		split_v := strings.SplitN(v, "=", 2)
		envMap[split_v[0]] = split_v[1]
	}

	return envMap, err
}
