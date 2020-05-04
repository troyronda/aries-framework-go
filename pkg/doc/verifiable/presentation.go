/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/xeipuuv/gojsonschema"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

const basePresentationSchema = `
{
  "required": [
    "@context",
    "type",
    "verifiableCredential"
  ],
  "properties": {
    "@context": {
      "oneOf": [
        {
          "type": "string",
          "const": "https://www.w3.org/2018/credentials/v1"
        },
        {
          "type": "array",
          "items": [
            {
              "type": "string",
              "const": "https://www.w3.org/2018/credentials/v1"
            }
          ],
          "uniqueItems": true,
          "additionalItems": {
            "oneOf": [
              {
                "type": "object"
              },
              {
                "type": "string"
              }
            ]
          }
        }
      ]
    },
    "id": {
      "type": "string",
      "format": "uri"
    },
    "type": {
      "oneOf": [
        {
          "type": "array",
          "items": [
            {
              "type": "string",
              "pattern": "^VerifiablePresentation$"
            }
          ],
          "minItems": 1
        },
        {
          "type": "string",
          "pattern": "^VerifiablePresentation$"
        }
      ],
      "additionalItems": {
        "type": "string"
      }
    },
    "verifiableCredential": {
      "anyOf": [
        {
          "type": "array"
        },
        {
          "type": "object"
        },
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ]
    },
    "holder": {
      "type": "string",
      "format": "uri"
    },
    "proof": {
      "anyOf": [
        {
          "type": "array",
          "items": [
            {
              "$ref": "#/definitions/proof"
            }
          ]
        },
        {
          "$ref": "#/definitions/proof"
        }
      ]
    },
    "refreshService": {
      "$ref": "#/definitions/typedID"
    }
  },
  "definitions": {
    "typedID": {
      "type": "object",
      "required": [
        "id",
        "type"
      ],
      "properties": {
        "id": {
          "type": "string",
          "format": "uri"
        },
        "type": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "array",
              "items": {
                "type": "string"
              }
            }
          ]
        }
      }
    },
    "proof": {
      "type": "object",
      "required": [
        "type"
      ],
      "properties": {
        "type": {
          "type": "string"
        }
      }
    }
  }
}
`

//nolint:gochecknoglobals
var basePresentationSchemaLoader = gojsonschema.NewStringLoader(basePresentationSchema)

// MarshalledCredential defines marshalled Verifiable Credential enclosed into Presentation.
// MarshalledCredential can be passed to verifiable.NewCredential().
type MarshalledCredential []byte

// Presentation Verifiable Presentation base data model definition
type Presentation struct {
	Context       []string
	CustomContext []interface{}
	ID            string
	Type          []string
	credentials   []*Credential
	rawCredentials []MarshalledCredential
	Holder        string
	Proofs        []Proof
}

// MarshalJSON converts Verifiable Presentation to JSON bytes.
func (vp *Presentation) MarshalJSON() ([]byte, error) {
	raw, err := vp.raw()
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of verifiable presentation: %w", err)
	}

	byteCred, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of verifiable presentation: %w", err)
	}

	return byteCred, nil
}

// JWTClaims converts Verifiable Presentation into JWT Presentation claims, which can be than serialized
// e.g. into JWS.
func (vp *Presentation) JWTClaims(audience []string, minimizeVP bool) (*JWTPresClaims, error) {
	return newJWTPresClaims(vp, audience, minimizeVP)
}

// Credentials returns current credentials of presentation.
//
// Note: Do not modify the returned credentials. You must use SetCredentials to set the credentials into the VP.
func (vp *Presentation) Credentials() []*Credential {
	return vp.credentials
}

// SetCredentials defines credentials of presentation.
// The credential could be string/byte (probably serialized JWT) or Credential structure.
func (vp *Presentation) SetCredentials(creds ...interface{}) error {
	var vpCreds []*Credential
	var vpCredsRaw []MarshalledCredential

	for i := range creds {
		switch rawVC := creds[i].(type) {
		case *Credential:
			cj, err := rawVC.MarshalJSON()
			if err != nil {
				return err
			}

			vpCreds = append(vpCreds, rawVC)
			vpCredsRaw = append(vpCredsRaw, cj)

		case []byte:
			vc, err := NewUnverifiedCredential(rawVC)
			if err != nil {
				return err
			}

			vpCreds = append(vpCreds, vc)
			vpCredsRaw = append(vpCredsRaw, rawVC)

		case string:
			vc, err := NewUnverifiedCredential([]byte(rawVC))
			if err != nil {
				return err
			}

			vpCreds = append(vpCreds, vc)
			vpCredsRaw = append(vpCredsRaw, []byte(rawVC))

		default:
			return errors.New("unsupported credential format")
		}
	}

	vp.credentials = vpCreds
	vp.rawCredentials = vpCredsRaw

	return nil
}

func (vp *Presentation) setCredentialsFromRaw(rawCreds []json.RawMessage) error {
	var creds []interface{}
	for _, c := range rawCreds {
		creds = append(creds, []byte(c))
	}

	return vp.SetCredentials(creds...)
}

// MarshalledCredentials provides marshalled credentials enclosed into Presentation in raw byte array format.
// They can be used to decode Credentials into struct.
func (vp *Presentation) MarshalledCredentials() ([]MarshalledCredential, error) {
	return vp.rawCredentials, nil
}

func (vp *Presentation) raw() (*rawPresentation, error) {
	creds, err := compactRawCreds(vp.rawCredentials)
	if err != nil {
		return nil, err
	}

	proof, err := proofsToRaw(vp.Proofs)
	if err != nil {
		return nil, err
	}

	return &rawPresentation{
		// TODO single value contexts should be compacted as part of Issue [#1730]
		// Not compacting now to support interoperability
		Context:    vp.Context,
		ID:         vp.ID,
		Type:       typesToRaw(vp.Type),
		Credential: creds,
		Holder:     vp.Holder,
		Proof:      proof,
	}, nil
}

// rawPresentation is a basic verifiable credential
type rawPresentation struct {
	Context    interface{}     `json:"@context,omitempty"`
	ID         string          `json:"id,omitempty"`
	Type       interface{}     `json:"type,omitempty"`
	Credential json.RawMessage `json:"verifiableCredential"`
	Holder     string          `json:"holder,omitempty"`
	Proof      json.RawMessage `json:"proof,omitempty"`
}

// presentationOpts holds options for the Verifiable Presentation decoding
type presentationOpts struct {
	publicKeyFetcher   PublicKeyFetcher
	disabledProofCheck bool
	ldpSuites          []verifier.SignatureSuite
	strictValidation   bool

	jsonldCredentialOpts
}

// PresentationOpt is the Verifiable Presentation decoding option
type PresentationOpt func(opts *presentationOpts)

// WithPresPublicKeyFetcher indicates that Verifiable Presentation should be decoded from JWS using
// the public key fetcher.
func WithPresPublicKeyFetcher(fetcher PublicKeyFetcher) PresentationOpt {
	return func(opts *presentationOpts) {
		opts.publicKeyFetcher = fetcher
	}
}

// WithPresEmbeddedSignatureSuites defines the suites which are used to check embedded linked data proof of VP.
func WithPresEmbeddedSignatureSuites(suites ...verifier.SignatureSuite) PresentationOpt {
	return func(opts *presentationOpts) {
		opts.ldpSuites = suites
	}
}

// WithDisabledPresentationProofCheck option for disabling of proof check.
func WithDisabledPresentationProofCheck() PresentationOpt {
	return func(opts *presentationOpts) {
		opts.disabledProofCheck = true
	}
}

// WithPresStrictValidation enabled strict JSON-LD validation of VP.
// In case of JSON-LD validation, the comparison of JSON-LD VP document after compaction with original VP one is made.
// In case of mismatch a validation exception is raised.
func WithPresStrictValidation() PresentationOpt {
	return func(opts *presentationOpts) {
		opts.strictValidation = true
	}
}

// NewPresentation creates an instance of Verifiable Presentation by reading a JSON document from bytes.
// It also applies miscellaneous options like custom decoders or settings of schema validation.
func NewPresentation(vpData []byte, opts ...PresentationOpt) (*Presentation, error) {
	// Apply options
	vpOpts := defaultPresentationOpts()

	for _, opt := range opts {
		opt(vpOpts)
	}

	vpDataDecoded, vpRaw, err := decodeRawPresentation(vpData, vpOpts)
	if err != nil {
		return nil, err
	}

	err = validateVP(vpDataDecoded, vpOpts)
	if err != nil {
		return nil, err
	}

	return newPresentation(vpRaw)
}

// NewUnverifiedPresentation decodes Verifiable Presentation from bytes which could be marshalled JSON or
// serialized JWT. It does not make a proof check though. Can be used for purposes of decoding of VP stored in a wallet.
// Please use this function with caution.
func NewUnverifiedPresentation(vpBytes []byte) (*Presentation, error) {
	// Apply options
	vpOpts := &presentationOpts{
		disabledProofCheck: true,
	}

	_, vpRaw, err := decodeRawPresentation(vpBytes, vpOpts)
	if err != nil {
		return nil, err
	}

	return newPresentation(vpRaw)
}

func newPresentation(vpRaw *rawPresentation) (*Presentation, error) {
	types, err := decodeType(vpRaw.Type)
	if err != nil {
		return nil, fmt.Errorf("fill presentation types from raw: %w", err)
	}

	context, customContext, err := decodeContext(vpRaw.Context)
	if err != nil {
		return nil, fmt.Errorf("fill presentation contexts from raw: %w", err)
	}

	rawCreds, err := jsonRawSlice(vpRaw.Credential)
	if err != nil {
		return nil, fmt.Errorf("decode credentials of presentation: %w", err)
	}

	proofs, err := decodeProof(vpRaw.Proof)
	if err != nil {
		return nil, fmt.Errorf("fill credential proof from raw: %w", err)
	}

	p := Presentation{
		Context:        context,
		CustomContext:  customContext,
		ID:             vpRaw.ID,
		Type:           types,
		Holder:         vpRaw.Holder,
		Proofs:         proofs,
	}

	err = p.setCredentialsFromRaw(rawCreds)
	if err != nil {
		return nil, fmt.Errorf("fill credential proof from raw: %w", err)
	}

	return &p, nil
}

func jsonRawSlice(j json.RawMessage) ([]json.RawMessage, error) {
	if j == nil {
		return nil, nil
	}

	var jsonArray []json.RawMessage
	err := json.Unmarshal(j, &jsonArray)
	if err == nil {
		return jsonArray, nil
	}

	return []json.RawMessage{j}, nil
}

func mapOpts(vpOpts *presentationOpts) *credentialOpts {
	return &credentialOpts{
		publicKeyFetcher:   vpOpts.publicKeyFetcher,
		disabledProofCheck: vpOpts.disabledProofCheck,
		ldpSuites:          vpOpts.ldpSuites,
	}
}

func validateVP(data []byte, opts *presentationOpts) error {
	err := validateVPJSONSchema(data)
	if err != nil {
		return err
	}

	return validateVPJSONLD(data, opts)
}

func validateVPJSONLD(vpBytes []byte, opts *presentationOpts) error {
	return compactJSONLD(string(vpBytes), &opts.jsonldCredentialOpts, opts.strictValidation)
}

func validateVPJSONSchema(data []byte) error {
	loader := gojsonschema.NewStringLoader(string(data))

	result, err := gojsonschema.Validate(basePresentationSchemaLoader, loader)
	if err != nil {
		return fmt.Errorf("validation of verifiable credential: %w", err)
	}

	if !result.Valid() {
		errMsg := describeSchemaValidationError(result, "verifiable presentation")
		return errors.New(errMsg)
	}

	return nil
}

func decodeRawPresentation(vpData []byte, vpOpts *presentationOpts) ([]byte, *rawPresentation, error) {
	vpStr := string(vpData)

	if jwt.IsJWS(vpStr) {
		if vpOpts.publicKeyFetcher == nil {
			return nil, nil, errors.New("public key fetcher is not defined")
		}

		vcDataFromJwt, rawCred, err := decodeVPFromJWS(vpStr, !vpOpts.disabledProofCheck, vpOpts.publicKeyFetcher)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding of Verifiable Presentation from JWS: %w", err)
		}

		return vcDataFromJwt, rawCred, nil
	}

	if jwt.IsJWTUnsecured(vpStr) {
		rawBytes, rawCred, err := decodeVPFromUnsecuredJWT(vpStr)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding of Verifiable Presentation from unsecured JWT: %w", err)
		}

		return rawBytes, rawCred, nil
	}

	vpBytes, vpRaw, err := decodeVPFromJSON(vpData)
	if err != nil {
		return nil, nil, err
	}

	// check that embedded proof is present, if not, it's not a verifiable presentation
	if !vpOpts.disabledProofCheck && vpRaw.Proof == nil {
		return nil, nil, errors.New("embedded proof is missing")
	}

	return vpBytes, vpRaw, err
}

func decodeVPFromJSON(vpData []byte) ([]byte, *rawPresentation, error) {
	// unmarshal VP from JSON
	raw := new(rawPresentation)

	err := json.Unmarshal(vpData, raw)
	if err != nil {
		return nil, nil, fmt.Errorf("JSON unmarshalling of verifiable presentation: %w", err)
	}

	return vpData, raw, nil
}

func defaultPresentationOpts() *presentationOpts {
	return &presentationOpts{}
}
