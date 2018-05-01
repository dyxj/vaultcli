// Copyright © 2018 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/dyxj/vaultcli/vcli/crypt"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
)

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypts and adds suffix .crypt",
	Long: `Encrypts a file, replacing it with an encrypted file with suffix .crypt
Example:
	vcli encrypt sometextfile.txt

Output file:
	sometextfile.txt.crypt
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return vcliEncrypt(args)
	},
}

func init() {
	rootCmd.AddCommand(encryptCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// encryptCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// encryptCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func vcliEncrypt(args []string) error {
	fmt.Println("Running file encryption")
	// Check args
	if len(args) < 1 {
		return fmt.Errorf("requires an argument. Which is the filepath")
	}

	// Check if encrypted file already exist
	newpath := args[0] + ".crypt"
	_, err := os.Stat(newpath)
	if !os.IsNotExist(err) {
		return fmt.Errorf("Encrypted file %s already exist, encryption aborted to avoid override", newpath)
	}

	// Open file
	f, err := os.Open(args[0])
	if err != nil {
		return fmt.Errorf("could not open file, %v", err)
	}
	defer f.Close()

	// Get file info
	finfo, err := f.Stat()
	if err != nil {
		return fmt.Errorf("couldn't get file info")
	}

	// Check if directory or file
	if finfo.IsDir() {
		return fmt.Errorf("path must point to a file")
	}

	// Make sure not .crypt file
	_, fname := filepath.Split(f.Name())
	fnames := strings.Split(fname, ".")
	if fnames[len(fnames)-1] == "crypt" {
		return fmt.Errorf("file is already encrypted")
	}

	// User Input Password
	fmt.Printf("Enter password: ")
	bpass, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		return fmt.Errorf("could not read password, %v", err)
	}
	fmt.Printf("\n")

	fmt.Printf("Confirm password: ")
	bpass2, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		return fmt.Errorf("could not read password, %v", err)
	}
	fmt.Printf("\n")

	if bytes.Compare(bpass, bpass2) != 0 {
		return fmt.Errorf("password mismatch")
	}

	// Read File
	b, err := ioutil.ReadAll(f)
	if err != nil {
		panic(err)
	}

	// Generate 32 byte key
	key32 := crypt.HashTo32Bytes([]byte(bpass))

	// Encrypt bytes
	ebytes, err := crypt.EncryptBytes(b, key32)
	if err != nil {
		return fmt.Errorf("couldn't encrypt file, %v", err)
	}

	// Save file
	err = ioutil.WriteFile(newpath, ebytes, finfo.Mode())
	if err != nil {
		return fmt.Errorf("couldn't save encrypted file, %v", err)
	}

	// Delete original file
	err = os.Remove(f.Name())
	if err != nil {
		return fmt.Errorf("couldn't delete original file, %v", err)
	}

	return nil
}
