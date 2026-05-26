package iam

import (
	"encoding/json"
	"fmt"
	"os"
)

func LoadSnapshot(path string) (*AccountSnapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening snapshot: %w", err)
	}
	defer f.Close()

	var snap AccountSnapshot
	if err := json.NewDecoder(f).Decode(&snap); err != nil {
		return nil, fmt.Errorf("parsing snapshot: %w", err)
	}
	return &snap, nil
}

func SaveSnapshot(snap *AccountSnapshot, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating snapshot file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(snap)
}
