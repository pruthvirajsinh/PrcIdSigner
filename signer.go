// signer
package PrcIdSigner

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"code.google.com/p/go.crypto/openpgp/packet"
	"crypto"
	"fmt"
)

// This function takes asciiarmored private key which will sign the public key
//Public key is also ascii armored,pripwd is password of private key in string
//This function will return ascii armored signed public key i.e. (pubkey+sign by prikey)
func SignPubKeyPKS(asciiPub string, asciiPri string, pripwd string) (asciiSignedKey string) {
	//get Private key from armor
	_, priEnt := getPri(asciiPri, pripwd) //pripwd is the password todecrypt the private key
	_, pubEnt := getPub(asciiPub)         //This will generate signature and add it to pubEnt
	usrIdstring := ""
	for _, uIds := range pubEnt.Identities {
		usrIdstring = uIds.Name

	}
	var prcPubEnt, prcPriEnt prcEntity
	prcPubEnt.Entity = &pubEnt
	prcPriEnt.Entity = &priEnt
	//prcPubEnt
	fmt.Println(usrIdstring)
	myConf := &packet.Config{DefaultHash: crypto.SHA1}
	errSign := prcPubEnt.PRCSignIdentity(usrIdstring, prcPriEnt, myConf)
	if errSign != nil {
		return
	}
	idnts := pubEnt.Identities
	for _, sss := range idnts {
		for _, srq := range sss.Signatures {
			asciiSignedKey = PubEntToAsciiArmor(pubEnt)
		}
	}
	return
}

//get packet.PublicKey and openpgp.Entity of Public Key from ascii armor
func getPub(asciiPub string) (pubKey packet.PublicKey, retEntity openpgp.Entity) {
	read1 := bytes.NewReader([]byte(asciiPub))
	entityList, errReadArm := openpgp.ReadArmoredKeyRing(read1)
	if errReadArm != nil {
		return
	}
	for _, pubKeyEntity := range entityList {
		if pubKeyEntity.PrimaryKey != nil {
			pubKey = *pubKeyEntity.PrimaryKey
			retEntity = *pubKeyEntity

		}
	}

	idnts := retEntity.Identities
	return
}

//get packet.PrivateKEy and openpgp.Entity of Private Key from ascii armor
func getPri(asciiPri string, pripwd string) (priKey packet.PrivateKey, priEnt openpgp.Entity) {
	read1 := bytes.NewReader([]byte(asciiPri))
	entityList, errReadArm := openpgp.ReadArmoredKeyRing(read1)
	if errReadArm != nil {
		fmt.Println("Reading PriKey ", errReadArm.Error())
		return
	}
	for _, can_pri := range entityList {
		smPr := can_pri.PrivateKey
		retEntity := can_pri
		if smPr == nil {
			fmt.Println("No Private Key")
			return
		}

		priKey = *smPr

		errDecr := priKey.Decrypt([]byte(pripwd))
		if errDecr != nil {
			fmt.Println("Decrypting ", errDecr.Error())
			return
		}
		retEntity.PrivateKey = &priKey
		priEnt = *retEntity
	}

	return
}

//Create ASscii Armor from openpgp.Entity
func PubEntToAsciiArmor(pubEnt openpgp.Entity) (asciiEntity string) {
	gotWriter := bytes.NewBuffer(nil)
	wr, errEncode := armor.Encode(gotWriter, openpgp.PublicKeyType, nil)
	if errEncode != nil {
		fmt.Println("Encoding Armor ", errEncode.Error())
		return
	}
	errSerial := pubEnt.Serialize(wr)
	if errSerial != nil {
		fmt.Println("Serializing PubKey ", errSerial.Error())
	}
	errClosing := wr.Close()
	if errClosing != nil {
		fmt.Println("Closing writer ", errClosing.Error())
	}
	asciiEntity = gotWriter.String()
	return
}
