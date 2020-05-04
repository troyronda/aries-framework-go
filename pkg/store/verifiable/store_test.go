/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/stretchr/testify/require"

	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

const sampleCredentialName = "sampleVCName"
const sampleCredentialID = "sampleVCID"
const samplePresentationName = "sampleVPName"
const samplePresentationID = "sampleVPID"

//nolint:gochecknoglobals,lll
var udCredential = `

{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "http://example.edu/credentials/1872",
  "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ],
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree"
    },
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  },

  "issuer": {
    "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
    "name": "Example University"
  },

  "issuanceDate": "2010-01-01T19:23:24Z",

  "expirationDate": "2020-01-01T19:23:24Z",

  "credentialStatus": {
    "id": "https://example.edu/status/24",
    "type": "CredentialStatusList2017"
  },

  "evidence": [{
    "id": "https://example.edu/evidence/f2aeec97-fc0d-42bf-8ca7-0548192d4231",
    "type": ["DocumentVerification"],
    "verifier": "https://example.edu/issuers/14",
    "evidenceDocument": "DriversLicense",
    "subjectPresence": "Physical",
    "documentPresence": "Physical"
  },{
    "id": "https://example.edu/evidence/f2aeec97-fc0d-42bf-8ca7-0548192dxyzab",
    "type": ["SupportingActivity"],
    "verifier": "https://example.edu/issuers/14",
    "evidenceDocument": "Fluid Dynamics Focus",
    "subjectPresence": "Digital",
    "documentPresence": "Digital"
  }],

  "termsOfUse": [
    {
      "type": "IssuerPolicy",
      "id": "http://example.com/policies/credential/4",
      "profile": "http://example.com/profiles/credential",
      "prohibition": [
        {
          "assigner": "https://example.edu/issuers/14",
          "assignee": "AllVerifiers",
          "target": "http://example.edu/credentials/3732",
          "action": [
            "Archival"
          ]
        }
      ]
    }
  ],

  "refreshService": {
    "id": "https://example.edu/refresh/3732",
    "type": "ManualRefreshService2018"
  }
}
`

//nolint:gochecknoglobals,lll
var udCredentialWithoutID = `

{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ],
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree"
    },
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  },

  "issuer": {
    "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
    "name": "Example University"
  },

  "issuanceDate": "2010-01-01T19:23:24Z",

  "expirationDate": "2020-01-01T19:23:24Z"
}
`

//nolint:lll
const udVerifiablePresentation = `{
        "@context": ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"],
        "type": ["VerifiablePresentation"],
        "verifiableCredential": [{
            "@context": ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"],
            "credentialSchema": [],
            "credentialStatus": {
                "id": "http://issuer.vc.rest.example.com:8070/status/1",
                "type": "CredentialStatusList2017"
            },
            "credentialSubject": {
                "degree": {"degree": "MIT", "type": "BachelorDegree"},
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "name": "Jayden Doe",
                "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
            },
            "id": "https://example.com/credentials/9315d0fd-da93-436e-9e20-2121f2821df3",
            "issuanceDate": "2020-03-16T22:37:26.544Z",
            "issuer": {
                "id": "did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg",
                "name": "alice_ca31684e-6cbb-40f9-b7e6-87e1ab5661ae"
            },
            "proof": {
                "created": "2020-04-08T21:19:02Z",
                "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..yGHHYmRp4mWd918SDSzmBDs8eq-SX7WPl8moGB8oJeSqEMmuEiI81D4s5-BPWGmKy3VlCsKJxYrTNqrEGJpNAQ",
                "proofPurpose": "assertionMethod",
                "type": "Ed25519Signature2018",
                "verificationMethod": "did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg#xqc3gS1gz1vch7R3RvNebWMjLvBOY-n_14feCYRPsUo"
            },
            "type": ["VerifiableCredential", "UniversityDegreeCredential"]
        }],
        "proof": {
            "created": "2020-04-08T17:19:05-04:00",
            "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..0CH8GwphcMoQ0JHCm1O8n9ctM-s8hTfTuOa-WeQFSmPipaO41pECe7pQ4zDM6sp08W59pkrTz_U1PrwLlUyoBw",
            "proofPurpose": "assertionMethod",
            "type": "Ed25519Signature2018",
            "verificationMethod": "did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg#xqc3gS1gz1vch7R3RvNebWMjLvBOY-n_14feCYRPsUo"
        }
    }
`

//nolint:lll
const udPresentation = `{
        "@context": ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"],
        "type": ["VerifiablePresentation"],
        "verifiableCredential": [{
            "@context": ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"],
            "credentialSchema": [],
            "credentialStatus": {
                "id": "http://issuer.vc.rest.example.com:8070/status/1",
                "type": "CredentialStatusList2017"
            },
            "credentialSubject": {
                "degree": {"degree": "MIT", "type": "BachelorDegree"},
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "name": "Jayden Doe",
                "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
            },
            "id": "https://example.com/credentials/9315d0fd-da93-436e-9e20-2121f2821df3",
            "issuanceDate": "2020-03-16T22:37:26.544Z",
            "issuer": {
                "id": "did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg",
                "name": "alice_ca31684e-6cbb-40f9-b7e6-87e1ab5661ae"
            },
            "proof": {
                "created": "2020-04-08T21:19:02Z",
                "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..yGHHYmRp4mWd918SDSzmBDs8eq-SX7WPl8moGB8oJeSqEMmuEiI81D4s5-BPWGmKy3VlCsKJxYrTNqrEGJpNAQ",
                "proofPurpose": "assertionMethod",
                "type": "Ed25519Signature2018",
                "verificationMethod": "did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg#xqc3gS1gz1vch7R3RvNebWMjLvBOY-n_14feCYRPsUo"
            },
            "type": ["VerifiableCredential", "UniversityDegreeCredential"]
        }]
    }
`

func TestNew(t *testing.T) {
	t.Run("test new store", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("test error from open store", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("failed to open store")},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open store")
		require.Nil(t, s)
	})
}

func TestSaveVC(t *testing.T) {
	t.Run("test save vc - success", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NoError(t, s.SaveCredential(sampleCredentialName, &verifiable.Credential{ID: "vc1"}))
	})

	t.Run("test save vc - error from store put", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string][]byte),
				ErrPut: fmt.Errorf("error put"),
			}),
		})
		require.NoError(t, err)
		err = s.SaveCredential(sampleCredentialName, &verifiable.Credential{ID: "vc1"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error put")
	})

	t.Run("test save vc - empty name", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string][]byte),
				ErrPut: fmt.Errorf("error put"),
			}),
		})
		require.NoError(t, err)
		err = s.SaveCredential("", &verifiable.Credential{ID: "vc1"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential name is mandatory")
	})

	t.Run("test save vc - error getting existing mapping for name", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string][]byte),
				ErrGet: fmt.Errorf("error get"),
			}),
		})
		require.NoError(t, err)
		err = s.SaveCredential(sampleCredentialName, &verifiable.Credential{ID: "vc1"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "get credential id using name")
	})

	t.Run("test save vc - name already exists", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NoError(t, s.SaveCredential(sampleCredentialName, &verifiable.Credential{ID: "vc1"}))

		err = s.SaveCredential(sampleCredentialName, &verifiable.Credential{ID: "vc2"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential name already exists")
	})
}

func TestGetVC(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		udVC, _, err := verifiable.NewCredential([]byte(udCredential))
		require.NoError(t, err)
		require.NoError(t, s.SaveCredential(sampleCredentialName, udVC))
		vc, err := s.GetCredential("http://example.edu/credentials/1872")
		require.NoError(t, err)
		require.Equal(t, vc.ID, "http://example.edu/credentials/1872")
	})

	t.Run("test success - vc without ID", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		udVC, _, err := verifiable.NewCredential([]byte(udCredentialWithoutID))
		require.NoError(t, err)
		require.NoError(t, s.SaveCredential(sampleCredentialName, udVC))

		id, err := s.GetCredentialIDByName(sampleCredentialName)
		require.NoError(t, err)
		require.NotEmpty(t, id)

		vc, err := s.GetCredential(id)
		require.NoError(t, err)
		require.NotEmpty(t, vc)
	})

	t.Run("test error from store get", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string][]byte),
				ErrGet: fmt.Errorf("error get"),
			}),
		})
		require.NoError(t, err)
		vc, err := s.GetCredential("vc1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error get")
		require.Nil(t, vc)
	})

	t.Run("test error from new credential", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NoError(t, s.SaveCredential(sampleCredentialName, &verifiable.Credential{ID: "vc1"}))
		require.NoError(t, err)
		vc, err := s.GetCredential("vc1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential type of unknown structure")
		require.Nil(t, vc)
	})
}

func TestGetCredentialIDBasedOnName(t *testing.T) {
	t.Run("test get credential based on name - success", func(t *testing.T) {
		rbytes, err := getRecord(sampleCredentialID, nil, nil)
		require.NoError(t, err)

		store := make(map[string][]byte)
		store[credentialNameDataKey(sampleCredentialName)] = rbytes

		s, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: store}},
		})
		require.NoError(t, err)

		id, err := s.GetCredentialIDByName(sampleCredentialName)
		require.NoError(t, err)
		require.Equal(t, sampleCredentialID, id)

		id, err = s.GetCredentialIDByName("some-random-id")
		require.Error(t, err)
		require.Empty(t, id)
		require.Contains(t, err.Error(), "fetch credential id based on name : data not found")
	})

	t.Run("test get credential based on name - db error", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string][]byte),
				ErrGet: fmt.Errorf("error get"),
			}),
		})
		require.NoError(t, err)

		id, err := s.GetCredentialIDByName(sampleCredentialName)
		require.Error(t, err)
		require.Contains(t, err.Error(), "fetch credential id based on name")
		require.Equal(t, "", id)
	})
}

func TestGetCredentials(t *testing.T) {
	t.Run("test get credentials", func(t *testing.T) {
		store := make(map[string][]byte)
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: store}},
		})
		require.NoError(t, err)

		records, err := s.GetCredentials()
		require.NoError(t, err)
		require.Equal(t, 0, len(records))

		err = s.SaveCredential(sampleCredentialName, &verifiable.Credential{ID: sampleCredentialID})
		require.NoError(t, err)

		records, err = s.GetCredentials()
		require.NoError(t, err)
		require.Equal(t, 1, len(records))
		require.Equal(t, records[0].Name, sampleCredentialName)
		require.Equal(t, records[0].ID, sampleCredentialID)

		// add some other values and make sure the GetCredential returns records as before
		store["dummy-value"] = []byte("dummy-key")

		records, err = s.GetCredentials()
		require.NoError(t, err)
		require.Equal(t, 1, len(records))

		n := 10
		for i := 0; i < n; i++ {
			err = s.SaveCredential(sampleCredentialName+strconv.Itoa(i),
				&verifiable.Credential{ID: sampleCredentialID + strconv.Itoa(i)})
			require.NoError(t, err)
		}

		records, err = s.GetCredentials()
		require.Equal(t, 1+n, len(records))
		require.NoError(t, err)
	})
}

func TestSaveVP(t *testing.T) {
	t.Run("test save vp - success", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NoError(t, s.SavePresentation(samplePresentationName, &verifiable.Presentation{ID: "vp1"}))
	})

	t.Run("test save vp - error from store put", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string][]byte),
				ErrPut: fmt.Errorf("error put"),
			}),
		})
		require.NoError(t, err)
		err = s.SavePresentation(samplePresentationName, &verifiable.Presentation{ID: "vp1"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error put")
	})

	t.Run("test save vp - empty name", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string][]byte),
				ErrPut: fmt.Errorf("error put"),
			}),
		})
		require.NoError(t, err)
		err = s.SavePresentation("", &verifiable.Presentation{ID: "vp1"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "presentation name is mandatory")
	})

	t.Run("test save vp - error getting existing mapping for name", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string][]byte),
				ErrGet: fmt.Errorf("error get"),
			}),
		})
		require.NoError(t, err)
		err = s.SavePresentation(samplePresentationName, &verifiable.Presentation{ID: "vp1"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "get presentation id using name")
	})

	t.Run("test save vp - name already exists", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NoError(t, s.SavePresentation(samplePresentationName, &verifiable.Presentation{ID: "vp1"}))

		err = s.SavePresentation(samplePresentationName, &verifiable.Presentation{ID: "vp2"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "presentation name already exists")
	})
}

func TestGetVP(t *testing.T) {
	t.Run("test success - save presentation", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		udVP, err := verifiable.NewPresentation([]byte(udPresentation),
			verifiable.WithDisabledPresentationProofCheck())
		require.NoError(t, err)
		require.NoError(t, s.SavePresentation(samplePresentationName, udVP))

		id, err := s.GetPresentationIDByName(samplePresentationName)
		require.NoError(t, err)
		require.NotEmpty(t, id)

		vp, err := s.GetPresentation(id)
		require.NoError(t, err)
		require.Equal(t, vp.Type[0], "VerifiablePresentation")

		/*
		require.NotEmpty(t, vp.Credentials())
		require.EqualValues(t, vp.Credentials()[0].(map[string]interface{})["id"],
			"https://example.com/credentials/9315d0fd-da93-436e-9e20-2121f2821df3")
		 */
	})

	t.Run("test success - save VP", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		udVP, err := verifiable.NewPresentation([]byte(udVerifiablePresentation))
		require.NoError(t, err)
		require.NoError(t, s.SavePresentation(samplePresentationName, udVP))

		id, err := s.GetPresentationIDByName(samplePresentationName)
		require.NoError(t, err)
		require.NotEmpty(t, id)

		vp, err := s.GetPresentation(id)
		require.NoError(t, err)
		require.Equal(t, vp.Type[0], "VerifiablePresentation")

/*
		require.NotEmpty(t, vp.Credentials())
		require.EqualValues(t, vp.Credentials()[0].(map[string]interface{})["id"],
			"https://example.com/credentials/9315d0fd-da93-436e-9e20-2121f2821df3")

 */
	})

	t.Run("test error from store get", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string][]byte),
				ErrGet: fmt.Errorf("error get"),
			}),
		})
		require.NoError(t, err)
		vp, err := s.GetPresentation("vpxyz")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error get")
		require.Nil(t, vp)
	})

	t.Run("test error from new presentation", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NoError(t, s.SavePresentation(samplePresentationName, &verifiable.Presentation{ID: "vp1"}))
		require.NoError(t, err)

		vc, err := s.GetPresentation("vp1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "verifiable presentation is not valid")
		require.Nil(t, vc)
	})
}

func TestGetPresentationIDBasedOnName(t *testing.T) {
	t.Run("test get presentation based on name - success", func(t *testing.T) {
		rbytes, err := getRecord(samplePresentationID, nil, nil)
		require.NoError(t, err)

		store := make(map[string][]byte)
		store[presentationNameDataKey(samplePresentationName)] = rbytes

		s, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: store}},
		})
		require.NoError(t, err)

		id, err := s.GetPresentationIDByName(samplePresentationName)
		require.NoError(t, err)
		require.Equal(t, samplePresentationID, id)
	})

	t.Run("test get presentation based on name - db error", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string][]byte),
				ErrGet: fmt.Errorf("error get"),
			}),
		})
		require.NoError(t, err)

		id, err := s.GetPresentationIDByName(samplePresentationName)
		require.Error(t, err)
		require.Contains(t, err.Error(), "fetch presentation id based on name")
		require.Equal(t, "", id)
	})
}

func TestGetPresentations(t *testing.T) {
	t.Run("test get presentations", func(t *testing.T) {
		store := make(map[string][]byte)
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: store}},
		})
		require.NoError(t, err)

		records, err := s.GetPresentations()
		require.NoError(t, err)
		require.Equal(t, 0, len(records))

		err = s.SavePresentation(samplePresentationName, &verifiable.Presentation{ID: samplePresentationID})
		require.NoError(t, err)

		records, err = s.GetPresentations()
		require.NoError(t, err)
		require.Equal(t, 1, len(records))
		require.Equal(t, records[0].Name, samplePresentationName)
		require.Equal(t, records[0].ID, samplePresentationID)

		// add some other values and make sure the GetCredential returns records as before
		store["dummy-value"] = []byte("dummy-key")

		records, err = s.GetPresentations()
		require.NoError(t, err)
		require.Equal(t, 1, len(records))

		n := 10
		for i := 0; i < n; i++ {
			err = s.SavePresentation(samplePresentationName+strconv.Itoa(i),
				&verifiable.Presentation{ID: samplePresentationID + strconv.Itoa(i)})
			require.NoError(t, err)
		}

		records, err = s.GetPresentations()
		require.NoError(t, err)
		require.Len(t, records, 1+n)
	})
}
