package gomat

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

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
func (p Point) as_bytes() []byte {
	o1 := elliptic.Marshal(elliptic.P256(), p.x, p.y)
	return o1
}
func (p *Point) from_bytes(in []byte ) {
	p.x, p.y = elliptic.Unmarshal(elliptic.P256(), in)
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


func serializeBytes(buf *bytes.Buffer, p []byte) {
	ln := uint64(len(p))
	binary.Write(buf, binary.LittleEndian, ln)
	buf.Write(p)
}

func createTT(context []byte, a, b string, m, n, x, y, z, v []byte, w0 []byte) []byte {
	var buf bytes.Buffer
	serializeBytes(&buf, context)
	serializeBytes(&buf, []byte(a))
	serializeBytes(&buf, []byte(b))

	serializeBytes(&buf, m)
	serializeBytes(&buf, n)
	serializeBytes(&buf, x)
	serializeBytes(&buf, y)
	serializeBytes(&buf, z)
	serializeBytes(&buf, v)
	serializeBytes(&buf, w0)
	return buf.Bytes()
}



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


func (ctx *SpakeCtx)gen_w(passcode int, salt []byte, iterations int) {
	pwd := pinToPasscode(uint32(passcode))
	ws := pbkdf2.Key(pwd, salt, iterations, 80, sha256.New)
	w0 := ws[:40]
	w1 := ws[40:80]

	curve := elliptic.P256()
	w0b := new(big.Int)
	w0b.SetBytes(w0)
	ctx.w0 = w0b.Mod(w0b, curve.Params().N).Bytes()

	w1b := new(big.Int)
	w1b.SetBytes(w1)
	ctx.w1 = w1b.Mod(w1b, curve.Params().N).Bytes()

}

func (ctx *SpakeCtx)gen_random_X() {
	ctx.x_random.SetBytes(create_random_bytes(32))
}
func (ctx *SpakeCtx)gen_random_Y() {
	ctx.y_random.SetBytes(create_random_bytes(32))
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

func (ctx *SpakeCtx)calc_hash(seed []byte) error {

	sh0sum := sha256_enc(seed)
	mbin := elliptic.Marshal(elliptic.P256(), M.x, M.y)
	nbin := elliptic.Marshal(elliptic.P256(), N.x, N.y)
	tt := createTT(sh0sum, "", "", mbin, nbin, ctx.X.as_bytes(), ctx.Y.as_bytes(), ctx.Z.as_bytes(), ctx.V.as_bytes(), ctx.w0)

	sh1sum := sha256_enc(tt)

	ctx.Ka = sh1sum[:16]
	ctx.Ke = sh1sum[16:32]

	key := hkdf_sha256(ctx.Ka, nil, []byte("ConfirmationKeys"), 32)

	ctx.cA = hmac_sha256_enc(ctx.Y.as_bytes(), key[:16])
	ctx.cB = hmac_sha256_enc(ctx.X.as_bytes(), key[16:])

	Xcryptkey := hkdf_sha256(ctx.Ke, nil, []byte("SessionKeys"), 16*3)
	ctx.decrypt_key = Xcryptkey[16:32]
	ctx.encrypt_key = Xcryptkey[:16]
	return nil
}

func newSpaceCtx() SpakeCtx {
	return SpakeCtx {
		curve: elliptic.P256(),
	}
}
