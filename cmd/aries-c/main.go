package main

import (
	"fmt"

	"C"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
)

var (
	_aries *aries.Aries //nolint: gochecknoglobals
)

func main() {
}

//export Initialize
func Initialize() {
	fmt.Println("Hello from aries-framework-go")

	a, err := aries.New()
	if err != nil {
		panic(err)
	}
	_aries = a
}

//export CreateInvitation
func CreateInvitation(outID *string) {
	fmt.Printf("CreateInvitation\n")

	ctx, err := _aries.Context()
	if err != nil {
		panic(err)
	}

	fmt.Println("Instantiating DID Exchange protocol client")
	c, err := didexchange.New(ctx)
	if err != nil {
		panic(err)
	}

	fmt.Println("Creating invitation")
	i, err := c.CreateInvitation("foo")
	if err != nil {
		panic(err)
	}

	fmt.Printf("ID: %s; RecipientKeys: %s\n", i.ID, i.RecipientKeys)
	*outID = i.ID
}