package sgx_server

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	fmt "fmt"
	"log"
	"time"

	"github.com/aead/cmac"
)

type Session struct {
	ias        *IAS
	mrenclaves [][32]byte

	id          uint64
	spid        []byte
	longTermKey *ecdsa.PrivateKey
	exgid       uint32
	gid         []byte
	ga          *PublicKey
	gb          *PublicKey

	// various session keys
	ephKey *ecdsa.PrivateKey
	kdk    []byte
	smk    []byte // MAC key
	vk     []byte
	sk     []byte
	mk     []byte

	// if sealCount goes over 2^{32}, it will throw an error
	aes       cipher.AEAD
	sealCount int

	lastUsed time.Time
}

const MSG4_SECRET = "REPLACE_ME_WITH_REAL_SECRET"

const EC_COORD_SIZE = 32
const EPID_GID_SIZE = 4

var SMK_LABEL = []byte{'S', 'M', 'K'}
var VK_LABEL = []byte{'V', 'K'}
var SK_LABEL = []byte{'S', 'K'}
var MK_LABEL = []byte{'M', 'K'}

var UNLINKABLE_QUOTE = []byte{0, 0}
var LINKABLE_QUOTE = []byte{1, 0}
var KDF_ID = []byte{1, 0}

const UNLINKABLE_QUOTE_INT = 0
const LINKABLE_QUOTE_INT = 1
const KDF_ID_INT = 1

func NewSession(mrenclaves [][32]byte, id uint64, spid []byte, longTermKey *ecdsa.PrivateKey, ias *IAS) *Session {
	s := &Session{
		ias:        ias,
		mrenclaves: mrenclaves,

		id:          id,
		spid:        spid,
		longTermKey: longTermKey,

		ephKey: generateKey(),

		sealCount: 0,
	}
	return s
}

func checkMsg1Format(msg1 *Msg1) bool {
	return len(msg1.Ga.X) == EC_COORD_SIZE &&
		len(msg1.Ga.Y) == EC_COORD_SIZE &&
		len(msg1.Gid) == EPID_GID_SIZE &&
		msg1.Msg0.SessionId == msg1.SessionId
}

func cmacWithKey(msg, key []byte) []byte {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		log.Fatal("Could not create AES for CMAC", err)
	}

	result, err := cmac.Sum(msg, block, aes.BlockSize)
	if err != nil {
		log.Fatal("Could not CMAC the message.")
	}
	return result
}

func (sn *Session) cmacA(a *A) []byte {
	concat := append(a.Gb.X, a.Gb.Y...)
	concat = append(concat, a.Spid...)
	concat = append(concat, a.QuoteType...)
	concat = append(concat, a.KdfId...)
	concat = append(concat, a.Signature.R...)
	concat = append(concat, a.Signature.S...)
	return cmacWithKey(concat, sn.smk)
}

func (sn *Session) cmacM(m *M) []byte {
	concat := append(m.Ga.X, m.Ga.Y...)
	concat = append(concat, m.PsSecurityProp...)
	concat = append(concat, m.Quote...)
	return cmacWithKey(concat, sn.smk)
}

func (sn *Session) cmacMsg4(msg4 *Msg4) []byte {
	b1 := []byte{0}
	if msg4.EnclaveTrusted {
		b1[0] = 1
	}
	b2 := []byte{0}
	if msg4.PseTrusted {
		b2[0] = 1
	}
	concat := append(b1, b2...)
	concat = append(concat, msg4.Pib...)
	concat = append(concat, msg4.Secret...)
	return cmacWithKey(concat, sn.smk)
}

func (sn *Session) hashReport() []byte {
	concat := append(sn.ga.X, sn.ga.Y...)
	concat = append(concat, sn.gb.X...)
	concat = append(concat, sn.gb.Y...)
	concat = append(concat, sn.vk...)
	hash := sha256.Sum256(concat)
	return hash[:]
}

func (sn *Session) ProcessMsg1(msg1 *Msg1) error {
	if !checkMsg1Format(msg1) {
		return errors.New("Malformed message 1")
	}

	sn.exgid = msg1.Msg0.Exgid
	sn.ga = msg1.Ga
	sn.gid = msg1.Gid

	sn.lastUsed = time.Now()
	return nil
}

func (sn *Session) CreateMsg2() (*Msg2, error) {
	gbx, gby, err := MarshalPublicKey(&sn.ephKey.PublicKey)
	if err != nil {
		return nil, err
	}
	sn.gb = &PublicKey{
		X: gbx,
		Y: gby,
	}

	keyMsg := append(gbx, gby...)
	keyMsg = append(keyMsg, sn.ga.X...)
	keyMsg = append(keyMsg, sn.ga.Y...)

	sum := sha256.Sum256(keyMsg)
	r, s, err := ecdsa.Sign(rand.Reader, sn.longTermKey, sum[:])
	if err != nil {
		return nil, err
	}

	// sometimes r and s are less than 32 bytes, but we need it to be exact
	var r32, s32 [32]byte
	rb, sb := r.Bytes(), s.Bytes()
	// convert to little endian
	reverse(rb)
	reverse(sb)
	copy(r32[32-len(rb):], rb)
	copy(s32[32-len(sb):], sb)

	sig := &Signature{
		R: r32[:],
		S: s32[:],
	}

	enclavePub, err := UnmarshalPublicKey(sn.ga.X, sn.ga.Y)
	if err != nil {
		return nil, err
	}

	sn.kdk, sn.smk = deriveLabelKey(sn.ephKey, enclavePub, SMK_LABEL)

	a := &A{
		Gb:        sn.gb,
		Spid:      sn.spid,
		QuoteType: UNLINKABLE_QUOTE,
		KdfId:     KDF_ID,
		Signature: sig,
	}

	sigRl, err := sn.ias.GetRevocationList(sn.gid)
	if err != nil {
		return nil, err
	}

	msg2 := &Msg2{
		A:         a,
		CmacA:     sn.cmacA(a),
		SigRlSize: uint32(len(sigRl)),
		SigRl:     sigRl,
	}

	sn.lastUsed = time.Now()
	return msg2, nil
}

func (sn *Session) ProcessMsg3(msg3 *Msg3) error {
	sn.vk = deriveLabelKeyFromBase(sn.kdk, VK_LABEL)

	if !bytes.Equal(msg3.M.Ga.X, sn.ga.X) {
		fmt.Println("X", msg3.M.Ga.X, sn.ga.X)
		return errors.New("Msg3 GA mismatch.")
	} else if !bytes.Equal(msg3.M.Ga.Y, sn.ga.Y) {
		fmt.Println("Y", msg3.M.Ga.Y, sn.ga.Y)
		return errors.New("Msg3 GA mismatch.")
	} else if !bytes.Equal(sn.cmacM(msg3.M), msg3.CmacM) {
		return errors.New("Msg3 MAC on M mismatch.")
	} else if !bytes.Equal(sn.hashReport(), msg3.M.Quote[368:368+32]) {
		return errors.New("Hash mismatch on report.")
	}

	var mr [32]byte
	copy(mr[:], msg3.M.Quote[112:112+32])

	found := false
	for _, valid := range sn.mrenclaves {
		if mr == valid {
			found = true
			break
		}
	}
	if !found {
		return errors.New("Invalid MREnclave.")
	}

	if err := sn.ias.VerifyQuote(msg3.M.Quote); err != nil {
		return err
	}

	sn.sk = deriveLabelKeyFromBase(sn.kdk, SK_LABEL)
	sn.mk = deriveLabelKeyFromBase(sn.kdk, MK_LABEL)

	block, err := aes.NewCipher(sn.sk)
	if err != nil {
		return err
	}
	sn.aes, err = cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// TODO: check DEBUG in the quote
	sn.lastUsed = time.Now()
	return nil
}

func (sn *Session) CreateMsg4() (*Msg4, error) {
	secret := []byte(MSG4_SECRET)
	ciphertext, err := sn.Seal(secret)
	if err != nil {
		return nil, err
	}

	// if it reaches this point, then the enclave must be trusted.
	// TODO: actually check whether PSE is trusted or not.
	// TODO: generate a Pib if EnclaveTrusted is not true
	msg4 := &Msg4{
		EnclaveTrusted: true,
		PseTrusted:     false,
		Pib:            []byte{},
		Secret:         ciphertext,
	}
	msg4.Cmac = sn.cmacMsg4(msg4)
	return msg4, nil
}

func (sn *Session) Seal(msg []byte) ([]byte, error) {
	if sn.sealCount > (1 << 32) {
		return nil, errors.New("Sealed too many messages")
	}

	nonce := make([]byte, 12)
	n, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	} else if n != 12 {
		return nil, errors.New("Insufficient amount of randomness for nonce.")
	}

	ciphertext := sn.aes.Seal(nil, nonce, msg, nil)
	sn.sealCount += 1
	sn.lastUsed = time.Now()
	return append(nonce, ciphertext...), nil
}

func (sn *Session) Open(ciphertext []byte) ([]byte, error) {
	sn.lastUsed = time.Now()
	return sn.aes.Open(nil, ciphertext[:12], ciphertext[12:], nil)
}
