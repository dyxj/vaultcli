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

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypts file and remove suffix .crypt",
	Long: `Decrypt files with suffix .crypt, replacing it with decrypted file.
Example:
	vcli decrypt sometextfile.txt.crypt

Output file:
	sometextfile.txt
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return vcliDecrypt(args)
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// decryptCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// decryptCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func vcliDecrypt(args []string) error {
	fmt.Println("Running file decryption")
	// Check args
	if len(args) < 1 {
		return fmt.Errorf("requires an argument. Which is the filepath")
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
	if fnames[len(fnames)-1] != "crypt" {
		return fmt.Errorf("file is not encrypted, file name should end with .crypt")
	}

	// User Input Password
	fmt.Printf("Enter password: ")
	bpass, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		return fmt.Errorf("could not read password, %v", err)
	}
	fmt.Printf("\n")

	// Read File
	b, err := ioutil.ReadAll(f)
	if err != nil {
		panic(err)
	}

	// Generate 32 byte key
	key32 := crypt.HashTo32Bytes([]byte(bpass))

	// Encrypt bytes
	ebytes, err := crypt.DecryptBytes(b, key32)

	// Save file
	newpath := strings.Join(fnames[:len(fnames)-1], ".")
	err = ioutil.WriteFile(newpath, ebytes, finfo.Mode())
	if err != nil {
		return fmt.Errorf("couldn't save encrypted file, %v", err)
	}

	// Delete unencrypted file
	err = os.Remove(args[0])
	if err != nil {
		return fmt.Errorf("couldn't delete unencrypted file, %v", err)
	}

	return nil
}
