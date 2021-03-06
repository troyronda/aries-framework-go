// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go/test/bdd

go 1.15

require (
	github.com/Microsoft/go-winio v0.4.16 // indirect
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/containerd/cgroups v0.0.0-20201119153540-4cbc285b3327 // indirect
	github.com/containerd/containerd v1.4.3 // indirect
	github.com/cucumber/godog v0.8.1
	github.com/fsouza/go-dockerclient v1.7.2
	github.com/golang/protobuf v1.4.3 // indirect
	github.com/golang/snappy v0.0.3 // indirect
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210304193329-f56b2cebc386
	github.com/hyperledger/aries-framework-go/component/storage/leveldb v0.0.0-20210305152013-b276ca413681
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210305152013-b276ca413681
	github.com/konsorten/go-windows-terminal-sequences v1.0.3 // indirect
	github.com/moby/sys/mount v0.2.0 // indirect
	github.com/piprate/json-gold v0.4.0
	github.com/trustbloc/sidetree-core-go v0.1.6-0.20210114211953-cf95801cfe3e
	go.opencensus.io v0.22.5 // indirect
	golang.org/x/sync v0.0.0-20201207232520-09787c993a3a // indirect
	nhooyr.io/websocket v1.8.3
)

replace github.com/hyperledger/aries-framework-go => ../..
