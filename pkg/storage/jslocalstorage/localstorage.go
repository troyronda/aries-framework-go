package jslocalstorage

import (
	"errors"
	"syscall/js"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// Provider leveldb implementation of storage.Provider interface
type Provider struct {
	dbPath string
}

// NewProvider instantiates Provider
func NewProvider(dbPath string) (*Provider, error) {
	return &Provider{dbPath: dbPath}, nil
}

// Close closes all stores created under this store provider
func (p *Provider) Close() error {
	return nil
}

// OpenStore opens and returns a store for given name space.
func (p *Provider) OpenStore(name string) (storage.Store, error) {
	return &store{name: name}, nil
}

// CloseStore closes level db store of given name
func (p *Provider) CloseStore(name string) error {
	return nil
}

type store struct {
	name string
}

// Put stores the key and the record
func (s *store) Put(k string, v []byte) error {
	if k == "" || v == nil {
		return errors.New("key and value are mandatory")
	}

	nsk := s.name + "___" + k

	js.Global().Get("localStorage").Call("setItem", nsk, string(v))
	return nil
}

// Get fetches the record based on key
func (s *store) Get(k string) ([]byte, error) {
	if k == "" {
		return nil, errors.New("key is mandatory")
	}

	nsk := s.name + "___" + k
	jsv := js.Global().Get("localStorage").Call("getItem", nsk)

	if !jsv.Truthy() {
		return nil, storage.ErrDataNotFound
	}

	return []byte(jsv.String()), nil
}

