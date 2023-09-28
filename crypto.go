package main

import (
	"bytes"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)


func pinToPasscode(pin uint32) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, pin)
	return buf.Bytes()
}

type Point struct {
	x *big.Int
	y *big.Int
}
func (p Point)dump() {
	fmt.Printf("  x: %v\n", p.x)
	fmt.Printf("  y: %v\n", p.y)
}

func (p Point) as_hex() string {
	o1 := elliptic.Marshal(elliptic.P256(), p.x, p.y)
	return hex.EncodeToString(o1)
}
func (p Point) as_bytes() []byte {
	o1 := elliptic.Marshal(elliptic.P256(), p.x, p.y)
	return o1
}
func (p *Point) from_bytes(in []byte ) {
	p.x, p.y = elliptic.Unmarshal(elliptic.P256(), in)
}

func (p Point) reset() {
	p.x.SetInt64(0)
	p.y.SetInt64(0)
}

var M Point
var N Point

func init() {
	mhex := "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
	mbin, _ := hex.DecodeString(mhex)
	M.x, M.y = elliptic.UnmarshalCompressed(elliptic.P256(), mbin)

	nhex := "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"
	nbin, _ := hex.DecodeString(nhex)
	N.x, N.y = elliptic.UnmarshalCompressed(elliptic.P256(), nbin)
}


func serializePoint(buf *bytes.Buffer, p []byte) {
	ln := uint64(len(p))
	binary.Write(buf, binary.LittleEndian, ln)
	buf.Write(p)
}

func createTT(context []byte, a, b string, m, n, x, y, z, v []byte, w0 []byte) []byte {
	var buf bytes.Buffer
	serializePoint(&buf, context)
	serializePoint(&buf, []byte(a))
	serializePoint(&buf, []byte(b))

	serializePoint(&buf, m)
	serializePoint(&buf, n)
	serializePoint(&buf, x)
	serializePoint(&buf, y)
	serializePoint(&buf, z)
	serializePoint(&buf, v)
	serializePoint(&buf, w0)

	return buf.Bytes()
}

/*
func genw0w1(password []byte, salt []byte, iterations int, keylen int) ([]byte, []byte){
	w0 := []byte {0xe6, 0x88, 0x7c, 0xf9, 0xbd, 0xfb, 0x75, 0x79, 0xc6, 0x9b, 0xf4, 0x79, 0x28, 0xa8,
		0x45, 0x14, 0xb5, 0xe3, 0x55, 0xac, 0x03, 0x48, 0x63, 0xf7, 0xff, 0xaf, 0x43, 0x90,
		0xe6, 0x7d, 0x79, 0x8c}
	w1 := []byte {0x24, 0xb5, 0xae, 0x4a, 0xbd, 0xa8, 0x68, 0xec, 0x93, 0x36, 0xff, 0xc3, 0xb7, 0x8e,
		0xe3, 0x1c, 0x57, 0x55, 0xbe, 0xf1, 0x75, 0x92, 0x27, 0xef, 0x53, 0x72, 0xca, 0x13,
		0x9b, 0x94, 0xe5, 0x12}
	return w0, w1
}*/

type SpakeCtx struct {
	curve elliptic.Curve
	w0 []byte
	w1 []byte
	x_random big.Int
	y_random big.Int
	X Point
	Y Point
	Z Point
	V Point
	L Point
	cA []byte
	cB []byte
	Ke []byte
	Ka []byte
	encrypt_key []byte
	decrypt_key []byte
}

/*
func (ctx *SpakeCtx)gen_w_test() {
	ctx.w0 = []byte {0xe6, 0x88, 0x7c, 0xf9, 0xbd, 0xfb, 0x75, 0x79, 0xc6, 0x9b, 0xf4, 0x79, 0x28, 0xa8,
		0x45, 0x14, 0xb5, 0xe3, 0x55, 0xac, 0x03, 0x48, 0x63, 0xf7, 0xff, 0xaf, 0x43, 0x90,
		0xe6, 0x7d, 0x79, 0x8c}
	ctx.w1 = []byte {0x24, 0xb5, 0xae, 0x4a, 0xbd, 0xa8, 0x68, 0xec, 0x93, 0x36, 0xff, 0xc3, 0xb7, 0x8e,
		0xe3, 0x1c, 0x57, 0x55, 0xbe, 0xf1, 0x75, 0x92, 0x27, 0xef, 0x53, 0x72, 0xca, 0x13,
		0x9b, 0x94, 0xe5, 0x12}
}*/

func (ctx *SpakeCtx)gen_w(passcode int, salt []byte, iterations int) {
	log.Println("gen")
	log.Println(passcode)
	log.Println(salt)
	log.Println(iterations)
	pwd := pinToPasscode(uint32(passcode))
	ws := pbkdf2.Key(pwd, salt, iterations, 80, sha256.New)
	w0 := ws[:40]
	w1 := ws[40:80]

	log.Printf("w0 %s\n", hex.EncodeToString(w0))
	log.Printf("w1 %s\n", hex.EncodeToString(w1))

	curve := elliptic.P256()
	w0b := new(big.Int)
	w0b.SetBytes(w0)
	ctx.w0 = w0b.Mod(w0b, curve.Params().N).Bytes()

	w1b := new(big.Int)
	w1b.SetBytes(w1)
	ctx.w1 = w1b.Mod(w1b, curve.Params().N).Bytes()

	log.Printf("w0a %s\n", hex.EncodeToString(w0))
	log.Printf("w0b %s\n", hex.EncodeToString(ctx.w0))
	log.Printf("w1 %s\n", hex.EncodeToString(ctx.w1))

}

func (ctx *SpakeCtx)gen_random_X() {
	ctx.x_random.SetBytes([]byte{0x8b, 0x0f, 0x3f, 0x38, 0x39, 0x05, 0xcf, 0x3a, 0x3b, 0xb9, 0x55, 0xef, 0x8f, 0xb6,
							     0x2e, 0x24, 0x84, 0x9d, 0xd3, 0x49, 0xa0, 0x5c, 0xa7, 0x9a, 0xaf, 0xb1, 0x80, 0x41,
		                         0xd3, 0x0c, 0xbd, 0xb6})
}
func (ctx *SpakeCtx)gen_random_Y() {
	ctx.y_random.SetBytes([]byte{0x2e, 0x08, 0x95, 0xb0, 0xe7, 0x63, 0xd6, 0xd5, 0xa9, 0x56, 0x44, 0x33, 0xe6, 0x4a,
		0xc3, 0xca, 0xc7, 0x4f, 0xf8, 0x97, 0xf6, 0xc3, 0x44, 0x52, 0x47, 0xba, 0x1b, 0xab,
		0x40, 0x08, 0x2a, 0x91})
}
func (ctx *SpakeCtx)calc_X() {
	// X=x*P+w0*M
	tx, ty := ctx.curve.ScalarBaseMult(ctx.x_random.Bytes())
	px, py := ctx.curve.ScalarMult(M.x, M.y, ctx.w0)
	ctx.X.x, ctx.X.y = ctx.curve.Add(tx, ty, px, py)
}
func (ctx *SpakeCtx)calc_Y() {
	//Y=y*P, pB=w*N+Y
	ypx, ypy := ctx.curve.ScalarMult(N.x, N.y, ctx.w0)
	ytx, yty := ctx.curve.ScalarBaseMult(ctx.y_random.Bytes())
	ctx.Y.x, ctx.Y.y = ctx.curve.Add(ytx, yty, ypx, ypy)
}

func (ctx *SpakeCtx)calc_ZV() {
	//A computes Z as h*x*(Y-w0*N), and V as h*w1*(Y-w0*N).
	wnx, wny := ctx.curve.ScalarMult(N.x, N.y, ctx.w0)
	wny = wny.Neg(wny)
	wny = wny.Mod(wny, ctx.curve.Params().P)
	znx, zny := ctx.curve.Add(ctx.Y.x, ctx.Y.y, wnx, wny)
	ctx.Z.x, ctx.Z.y = ctx.curve.ScalarMult(znx, zny, ctx.x_random.Bytes())


	ctx.V.x, ctx.V.y = ctx.curve.ScalarMult(znx, zny, ctx.w1)

}

func (ctx *SpakeCtx)calc_ZVb() {
	//B computes Z as y(X-w0*M) and V as yL
	unx, uny := ctx.curve.ScalarMult(M.x, M.y, ctx.w0)
	uny = uny.Neg(uny)
	uny = uny.Mod(uny, ctx.curve.Params().P)
	zznx, zzny := ctx.curve.Add(ctx.X.x, ctx.X.y, unx, uny)
	ctx.Z.x, ctx.Z.y = ctx.curve.ScalarMult(zznx, zzny, ctx.y_random.Bytes())
	ctx.L.x, ctx.L.y = ctx.curve.ScalarBaseMult(ctx.w1)
	ctx.V.x, ctx.V.y = ctx.curve.ScalarMult(ctx.L.x, ctx.L.y, ctx.y_random.Bytes())
}

func (ctx *SpakeCtx)calc_hash(seed []byte) {
	sh0 := sha256.New()
	sh0.Write(seed)


	sh0sum := sh0.Sum(nil)
	mbin := elliptic.Marshal(elliptic.P256(), M.x, M.y)
	nbin := elliptic.Marshal(elliptic.P256(), N.x, N.y)
	//tt := createTT("SPAKE2+-P256-SHA256-HKDF draft-01", "client", "server", mbin, nbin, ctx.X.as_bytes(), ctx.Y.as_bytes(), ctx.Z.as_bytes(), ctx.V.as_bytes(), ctx.w0)
	tt := createTT(sh0sum, "", "", mbin, nbin, ctx.X.as_bytes(), ctx.Y.as_bytes(), ctx.Z.as_bytes(), ctx.V.as_bytes(), ctx.w0)

	sh1 := sha256.New()
	sh1.Write(tt)
	sh1sum := sh1.Sum(nil)
	log.Printf("hash: %v\n", hex.EncodeToString(sh1sum))
	ctx.Ka = sh1sum[:16]
	ctx.Ke = sh1sum[16:32]
	log.Printf("ka: %v\n", hex.EncodeToString(ctx.Ka))
	log.Printf("ke: %v\n", hex.EncodeToString(ctx.Ke))

	//(salt, ikm, info []byte
	hkdfz := hkdf.New(sha256.New, ctx.Ka, nil, []byte("ConfirmationKeys"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdfz, key); err != nil {
		panic(err)
	}
	//log.Printf("kca %v\n", hex.EncodeToString(key[:16]))
	//log.Printf("kcb %v\n", hex.EncodeToString(key[16:]))

	mac := hmac.New(sha256.New, key[:16])
	mac.Write(ctx.Y.as_bytes())
	ctx.cA = mac.Sum(nil)
	log.Printf("ca %v\n", hex.EncodeToString(ctx.cA))

	mac = hmac.New(sha256.New, key[16:])
	mac.Write(ctx.X.as_bytes())
	ctx.cB = mac.Sum(nil)
	log.Printf("cb %v\n", hex.EncodeToString(ctx.cB))

	//hm := hmac.New(h func() hash.Hash, key []byte)
	//hkdf2 := hkdf.New(sha256.New, ctx.Ka, nil, []byte("SessionKeys"))
	hkdf2 := hkdf.New(sha256.New, ctx.Ke, nil, []byte("SessionKeys"))
	Xcryptkey := make([]byte, 16*3)
	if _, err := io.ReadFull(hkdf2, Xcryptkey); err != nil {
		panic(err)
	}
	ctx.decrypt_key = Xcryptkey[16:32]
	ctx.encrypt_key = Xcryptkey[:16]
}

func newSpaceCtx() SpakeCtx {
	return SpakeCtx {
		curve: elliptic.P256(),
	}
}

/*
func test3() {
	ctx := newSpaceCtx()
	ctx.gen_w_test()
	ctx.gen_random_X()
	ctx.gen_random_Y()
	ctx.calc_X()
	ctx.calc_Y()
	ctx.calc_ZV()
	log.Printf("X: %s\n", ctx.X.as_hex())
	log.Printf("Y: %s\n", ctx.Y.as_hex())
	log.Printf("Z: %s\n", ctx.Z.as_hex())
	log.Printf("V: %s\n", ctx.V.as_hex())

	ctx.Z.reset()
	ctx.V.reset()
	ctx.calc_ZVb()
	log.Printf("Z: %s\n", ctx.Z.as_hex())
	log.Printf("V: %s\n", ctx.V.as_hex())

	ctx.calc_hash([]byte("SPAKE2+-P256-SHA256-HKDF draft-01"))

	ctx.gen_w(123456, []byte{0x4, 0xa1, 0xd2, 0xc6, 0x11, 0xf0, 0xbd, 0x36, 0x78, 0x67, 0x79, 0x7b, 0xfe, 0x82, 0x36, 0x0}, 2000)
}

*/