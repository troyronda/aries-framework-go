/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package http

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/rs/cors"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
)

var logger = log.New("aries-framework/http")

// TODO https://github.com/hyperledger/aries-framework-go/issues/891 Support for Transport Return Route (Duplex)

// NewInboundHandler will create a new handler to enforce Did-Comm HTTP transport specs
// then routes processing to the mandatory 'msgHandler' argument.
//
// Arguments:
// * 'msgHandler' is the handler function that will be executed with the inbound request payload.
//    Users of this library must manage the handling of all inbound payloads in this function.
func NewInboundHandler(prov transport.Provider) (http.Handler, error) {
	if prov == nil || prov.InboundMessageHandler() == nil {
		logger.Errorf("Error creating a new inbound handler: message handler function is nil")
		return nil, errors.New("creation of inbound handler failed")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		processPOSTRequest(w, r, prov)
	}), nil
}

func processPOSTRequest(w http.ResponseWriter, r *http.Request, prov transport.Provider) {
	if valid := validateHTTPMethod(w, r); !valid {
		return
	}

	if valid := validatePayload(r, w); !valid {
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logger.Errorf("Error reading request body: %s - returning Code: %d", err, http.StatusInternalServerError)
		http.Error(w, "Failed to read payload", http.StatusInternalServerError)

		return
	}

	unpackMsg, err := prov.Packager().UnpackMessage(body)
	if err != nil {
		logger.Errorf("failed to unpack msg: %s - returning Code: %d", err, http.StatusInternalServerError)
		http.Error(w, "failed to unpack msg", http.StatusInternalServerError)

		return
	}

	messageHandler := prov.InboundMessageHandler()

	err = messageHandler(unpackMsg.Message, unpackMsg.ToDID, unpackMsg.FromDID)
	if err != nil {
		// TODO https://github.com/hyperledger/aries-framework-go/issues/271 HTTP Response Codes based on errors
		//  from service
		logger.Errorf("incoming msg processing failed: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusAccepted)
	}
}

// validatePayload validate and get the payload from the request
func validatePayload(r *http.Request, w http.ResponseWriter) bool {
	if r.ContentLength == 0 { // empty payload should not be accepted
		http.Error(w, "Empty payload", http.StatusBadRequest)
		return false
	}

	return true
}

// validateHTTPMethod validate HTTP method and content-type
func validateHTTPMethod(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != "POST" {
		http.Error(w, "HTTP Method not allowed", http.StatusMethodNotAllowed)
		return false
	}

	ct := r.Header.Get("Content-type")
	if ct != commContentType {
		http.Error(w, fmt.Sprintf("Unsupported Content-type \"%s\"", ct), http.StatusUnsupportedMediaType)
		return false
	}

	return true
}

// Inbound http type.
type Inbound struct {
	externalAddr string
	server       *http.Server
}

// NewInbound creates a new HTTP inbound transport instance.
func NewInbound(internalAddr, externalAddr string) (*Inbound, error) {
	if internalAddr == "" {
		return nil, errors.New("http address is mandatory")
	}

	if externalAddr == "" {
		return &Inbound{externalAddr: internalAddr, server: &http.Server{Addr: internalAddr}}, nil
	}

	return &Inbound{externalAddr: externalAddr, server: &http.Server{Addr: internalAddr}}, nil
}

// Start the http server.
func (i *Inbound) Start(prov transport.Provider) error {
	inboundHandler, err := NewInboundHandler(prov)
	if err != nil {
		return fmt.Errorf("HTTP server start failed: %w", err)
	}

	handler := cors.New(
		cors.Options{
			AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodHead},
		},
	).Handler(inboundHandler)

	i.server.Handler = handler

	go func() {
		if err := i.server.ListenAndServe(); err != http.ErrServerClosed {
			logger.Fatalf("HTTP server start with address [%s] failed, cause:  %s", i.server.Addr, err)
		}
	}()

	return nil
}

// Stop the http server.
func (i *Inbound) Stop() error {
	if err := i.server.Shutdown(context.Background()); err != nil {
		return fmt.Errorf("HTTP server shutdown failed: %w", err)
	}

	return nil
}

// Endpoint provides the http connection details.
func (i *Inbound) Endpoint() string {
	// return http prefix as framework only supports http
	return i.externalAddr
}
