package sgx_server

import (
	"encoding/hex"
	"io/ioutil"
	"log"
	"path"
)

func ReadMREnclaves(dir string) [][32]byte {
	mrs, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatal("Could not read mrenclaves directory:", err)
	}

	mrenclaves := make([][32]byte, len(mrs))
	for i, mr := range mrs {
		mhex, err := ioutil.ReadFile(path.Join(dir, mr.Name()))
		if err != nil {
			log.Fatal("Could not read the mrenclave.")
		}
		mrenclave := make([]byte, hex.DecodedLen(len(mhex)))
		l, err := hex.Decode(mrenclave, mhex)
		if err != nil {
			log.Fatal("Could not parse the hex mrenclave.")
		}
		if l != 32 {
			log.Fatal("MREnclave files should be 32 bytes, but instead got", l)
		}

		copy(mrenclaves[i][:], mrenclave[:])
	}
	return mrenclaves
}

func ReadSPID(fn string) []byte {
	shex, err := ioutil.ReadFile(fn)
	if err != nil {
		log.Fatal("Could not read the spid.")
	}
	spid := make([]byte, hex.DecodedLen(len(shex)))
	l, err := hex.Decode(spid, shex)
	if err != nil {
		log.Fatal("Could not parse the hex spid:", err)
	} else if l != 16 {
		log.Fatal("MREnclave files should be 16 bytes, but instead got", l)
	}

	return spid
}

func ReadSubscription(fn string) string {
	sb, err := ioutil.ReadFile(fn)
	if err != nil {
		log.Fatal("Could not read the subscription key.")
	}
	return string(sb)
}
