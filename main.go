// gpgSigner project main.go
package main

import (
	"fmt"
	"os"
)
//Just a small program to display use of the method
func main() {
//Get ur keys and call following
	armor := SignPubKeyPKS(Prc_original_key, Pks_pri_key_armor, Pripwd)

	file, err := os.Create("exported_pubkey.pub")
	if err != nil {
		// handle the error here
		fmt.Println(err.Error())
		return
	}
	defer file.Close()

	file.WriteString(armor)

	fmt.Println("Wrote to File", armor)
	//getPub(prc_pks_signed_key)
}
