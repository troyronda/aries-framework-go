// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/hyperledger/aries-framework-go/pkg/store/did (interfaces: ConnectionStore)

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	did "github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// MockConnectionStore is a mock of ConnectionStore interface.
type MockConnectionStore struct {
	ctrl     *gomock.Controller
	recorder *MockConnectionStoreMockRecorder
}

// MockConnectionStoreMockRecorder is the mock recorder for MockConnectionStore.
type MockConnectionStoreMockRecorder struct {
	mock *MockConnectionStore
}

// NewMockConnectionStore creates a new mock instance.
func NewMockConnectionStore(ctrl *gomock.Controller) *MockConnectionStore {
	mock := &MockConnectionStore{ctrl: ctrl}
	mock.recorder = &MockConnectionStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockConnectionStore) EXPECT() *MockConnectionStoreMockRecorder {
	return m.recorder
}

// GetDID mocks base method.
func (m *MockConnectionStore) GetDID(arg0 string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetDID", arg0)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetDID indicates an expected call of GetDID.
func (mr *MockConnectionStoreMockRecorder) GetDID(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetDID", reflect.TypeOf((*MockConnectionStore)(nil).GetDID), arg0)
}

// SaveDID mocks base method.
func (m *MockConnectionStore) SaveDID(arg0 string, arg1 ...string) error {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0}
	for _, a := range arg1 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "SaveDID", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// SaveDID indicates an expected call of SaveDID.
func (mr *MockConnectionStoreMockRecorder) SaveDID(arg0 interface{}, arg1 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0}, arg1...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveDID", reflect.TypeOf((*MockConnectionStore)(nil).SaveDID), varargs...)
}

// SaveDIDByResolving mocks base method.
func (m *MockConnectionStore) SaveDIDByResolving(arg0 string, arg1 ...string) error {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0}
	for _, a := range arg1 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "SaveDIDByResolving", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// SaveDIDByResolving indicates an expected call of SaveDIDByResolving.
func (mr *MockConnectionStoreMockRecorder) SaveDIDByResolving(arg0 interface{}, arg1 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0}, arg1...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveDIDByResolving", reflect.TypeOf((*MockConnectionStore)(nil).SaveDIDByResolving), varargs...)
}

// SaveDIDFromDoc mocks base method.
func (m *MockConnectionStore) SaveDIDFromDoc(arg0 *did.Doc) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SaveDIDFromDoc", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SaveDIDFromDoc indicates an expected call of SaveDIDFromDoc.
func (mr *MockConnectionStoreMockRecorder) SaveDIDFromDoc(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveDIDFromDoc", reflect.TypeOf((*MockConnectionStore)(nil).SaveDIDFromDoc), arg0)
}