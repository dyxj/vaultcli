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

var boolPrintOnly bool

func init() {
	rootCmd.AddCommand(decryptCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// decryptCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// decryptCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	decryptCmd.Flags().BoolVarP(&boolPrintOnly, "print", "p", false, "print only")
}

func vcliDecrypt(args []string) error {
	fmt.Println("Running file decryption")
	// Check args
	if len(args) < 1 {
		return fmt.Errorf("requires an argument. Which is the filepath")
	}

	// Make sure it is a .crypt file
	_, fname := filepath.Split(args[0])
	fnames := strings.Split(fname, ".")
	if fnames[len(fnames)-1] != "crypt" {
		return fmt.Errorf("file is not encrypted, file name should end with .crypt")
	}

	// Check if decrypted file already exist
	newpath := strings.Join(fnames[:len(fnames)-1], ".")
	if _, err := os.Stat(newpath); !os.IsNotExist(err) {
		return fmt.Errorf("Decrypted file %s already exist, decryption aborted to avoid override", newpath)
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

	// User Input Password
	fmt.Printf("Enter password: ")
	bpass, err := terminal.ReadPassword(int(syscall.Stdin))
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

	// Decrypt bytes
	ebytes, err := crypt.DecryptBytes(b, key32)
	if err != nil {
		return fmt.Errorf("couldn't decrypt file, %v", err)
	}

	if boolPrintOnly {
		fmt.Println(string(ebytes))
		return nil
	}

	// Save file
	err = ioutil.WriteFile(newpath, ebytes, finfo.Mode())
	if err != nil {
		return fmt.Errorf("couldn't save decrypted file, %v", err)
	}

	// Close original encrypted file, to allow for delete(Windows)
	f.Close()

	// Delete original encrypted file
	err = os.Remove(f.Name())
	if err != nil {
		return fmt.Errorf("couldn't delete original encrypted file, %v", err)
	}

	return nil
}
