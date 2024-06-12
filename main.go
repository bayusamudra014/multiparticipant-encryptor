package main

import (
	"fmt"
	"os"

	"github.com/akamensky/argparse"
	"github.com/bayusamudra5502/multiparticipant-encryptor/cmd"
	"golang.org/x/term"
)

func main() {
	parser := argparse.NewParser("multiparticipant-encryptor", "Encrypt and decrypt files with multiple participants")
	generateKey := parser.Flag(
		"g",
		"generate-key",
		&argparse.Options{
			Required: false,
			Help:     "Generate Key Pair",
			Default:  false,
		},
	)
	encrypt := parser.Flag(
		"e",
		"encrypt",
		&argparse.Options{
			Required: false,
			Help:     "Encrypt a file",
			Default:  false,
		},
	)
	decrypt := parser.Flag(
		"d",
		"decrypt",
		&argparse.Options{
			Required: false,
			Help:     "Decrypt a file",
			Default:  false,
		},
	)
	replace := parser.Flag(
		"r",
		"replace",
		&argparse.Options{
			Required: false,
			Help:     "Replace text in a file",
			Default:  false,
		},
	)
	public := parser.String(
		"p",
		"public",
		&argparse.Options{
			Required: false,
			Help:     "Public key file path",
		},
	)
	private := parser.String(
		"k",
		"private",
		&argparse.Options{
			Required: false,
			Help:     "Private key file path",
		},
	)
	input := parser.String(
		"i",
		"input",
		&argparse.Options{
			Required: false,
			Help:     "Input plaintext file",
		},
	)
	output := parser.String(
		"o",
		"output",
		&argparse.Options{
			Required: false,
			Help:     "Output encrypted file",
		},
	)
	acl := parser.String(
		"a",
		"acl",
		&argparse.Options{
			Required: false,
			Help:     "Access control list file",
		},
	)

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Println(parser.Usage(err))
		return
	}

	if *generateKey {
		if *public == "" && *private == "" {
			fmt.Println("Error: Public and private key file paths are required")
			return
		}

		generateKeyMenu(*public, *private)
		return
	}

	if *encrypt {
		if *input == "" && *output == "" && *private == "" && *acl == "" {
			fmt.Println("Error: Input, output, private key, and ACL file paths are required")
			return
		}

		encryptMenu(
			*input,
			*output,
			*private,
			*acl,
		)
		return
	}

	if *decrypt {
		decryptMenu()
		return
	}

	if *replace {
		replaceMenu()
		return
	}

	fmt.Println("Error: No command specified")
}

func generateKeyMenu(public string, private string) {
	fmt.Print("Enter password: ")
	password, err := term.ReadPassword(0)
	fmt.Println()

	if err != nil {
		fmt.Printf("Error: reading password failed: %s\n", err)
		return
	}

	fmt.Print("Retype password: ")
	password2, err := term.ReadPassword(0)
	fmt.Println()

	if err != nil {
		fmt.Printf("Error: reading password failed: %s\n", err)
		return
	}

	if string(password) != string(password2) {
		fmt.Println("Error: Passwords do not match")
		return
	}

	if err := cmd.GenerateKeyPairFile(public, private, password); err != nil {
		fmt.Printf("Error: generating key pair failed: %s\n", err)
		return
	}

	fmt.Println("Key pair generated successfully")
}

func encryptMenu(
	inputFile string,
	outputFile string,
	privateKey string,
	aclFile string,
) {
	acls, err := cmd.ParseACL(aclFile)

	if err != nil {
		fmt.Printf("Error: parsing ACL file failed: %s\n", err)
		return
	}

	fmt.Print("Enter password: ")
	password, err := term.ReadPassword(0)
	fmt.Println()

	if err != nil {
		fmt.Printf("Error: reading password failed: %s\n", err)
		return
	}

	if err := cmd.EncryptFile(inputFile, outputFile, privateKey, password, acls); err != nil {
		fmt.Printf("Error: encrypting file failed: %s\n", err)
		return
	}

	fmt.Println("File encrypted successfully:", outputFile)
}

func decryptMenu() {
}

func replaceMenu() {
}
