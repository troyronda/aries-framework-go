package aries

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/jslocalstorage"
)

func storeProvider() (storage.Provider, error) {
	storeProv, err := jslocalstorage.NewProvider(dbPath)
	if err != nil {
		return nil, fmt.Errorf("leveldb provider initialization failed : %w", err)
	}
	return storeProv, nil
}