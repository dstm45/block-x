package handler

import (
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

type Policy struct {
	Name                  string            `yaml:"name"`
	Description           string            `yaml:"description"`
	RestrictedFiles       []FilePolicy      `yaml:"restricted_files"`
	RestrictedDirectories []DirectoryPolicy `yaml:"restricted_directories"`
}

type FilePolicy struct {
	Paths []string      `yaml:"paths"`
	Read  AccessControl `yaml:"read"`
	Write AccessControl `yaml:"write"`
}

type DirectoryPolicy struct {
	Paths []string      `yaml:"paths"`
	Read  AccessControl `yaml:"read"`
	Write AccessControl `yaml:"write"`
}

type AccessControl struct {
	Allow *Permissions `yaml:"allow"`
}

type Permissions struct {
	UserUID     []int    `yaml:"user_uid"`
	BinaryPaths []string `yaml:"binary_paths"`
}

func NewPolicy() *Policy {
	return new(Policy)
}

func (p *Policy) Parse(configPath string) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalln("Erreur lors de la lecture de la configuration en yaml. err:", err)
	}
	err = yaml.Unmarshal(data, &p)
	if err != nil {
		log.Println("Erreur lors de l'extraction de la police de sécurité. err:", err)
	}
}
