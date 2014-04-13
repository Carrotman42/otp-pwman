package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"crypto/sha256"
	"code.google.com/p/go.crypto/pbkdf2"
	"crypto/rand"
)

const HumanReadOutput = true

// Sources of entropy
var books = [OtpLen]string{
	"data/beo.txt",
	"data/kama.txt",
	"data/moby.txt",
	"data/myth.txt",
}

func MustOpen(i int) io.Reader {
	if f, err := os.Open(books[i]); err != nil {
		panic(err)
	} else {
		return f
	}
}

func getOtpSrcs(ignore int64) (ret [OtpLen]ByteSrc) {
	for i := range ret {
		c := MustOpen(i)
		_, e := io.CopyN(ioutil.Discard, c, ignore+6000) //ignore the first bit of text too in order to ensure the copyright notice isn't part of the otp
		if e != nil {
			panic(e)
		}
		ret[i] = Domainify(c)
	}
	return ret
}

// Un-encrypted structure
type PasswordStore map[string]string

func (p *PasswordStore) Load(pass, salt []byte, src ByteSrc) {
	t := make(PasswordStore)
	*p = t

	// Splits the fields up according to tabs and newlines
	splitter := func() (byte, bool) {
		if c, ok := src(); ok && c != '\t' && c != '\n' && c != '\r' {
			return c, true
		}
		return 0, false
	}
	otp := getOtp(pass, salt)
	for {
		var key, val bbuf
		Pad(key.Append, splitter, otp, false)
		if len(key) == 0 {
			// Done!
			break
		}
		Pad(val.Append, splitter, otp, false)

		t[string(key)] = string(val)
	}
}

func getOtp(pass, salt []byte) ByteSrc {
	hash := CalcHash(pass, salt)
	start, ok := hash.Next(16)
	if !ok {
		panic("Hash too short")
	}
	return JoinOtps(hash, getOtpSrcs(int64(start)))
}

// TODO: Encrypt the key of the PasswordStore differently/separately
//    I want this because I don't want any sort of patterns to be detectable, and since the keys will probably be
//    websites that's a bit of a pattern. Low priority (super paranoid).
func (p PasswordStore) Store(pass, salt []byte, dst ByteDst) {
	otp := getOtp(pass, salt)
	for k, v := range p {
		Pad(dst, StrSrc(k), otp, true)
		dst('\t')
		Pad(dst, StrSrc(v), otp, true)
		dst('\n')
	}
}

func StrSrc(s string) ByteSrc {
	r := bbuf(s)
	return r.Read
}

// Changes how long the hashing function takes as well as
//    then length of the has it generates
const (
	HashIts = 4096
	HashLen = sha256.Size*50
)

func CalcHash(pass, salt []byte) *BitBuf {
	password := pass
	fmt.Printf("Calculating hash (iters: %v, size: %v)...\n", HashIts, HashLen)
	d := pbkdf2.Key(password, salt, HashIts, HashLen, sha256.New)
	//fmt.Println(len(d))
	
	hbuf := bbuf(d)
	return &BitBuf{src: hbuf.Read}
}

func NewPass(l int, ignore []byte) string {
	ret := make([]byte, l)
	src := ReaderToSrc(rand.Reader)
	for i := range ret {
nch:	for {
			if v, ok := src(); !ok {
				panic("ran out of entropy!")
			} else {
				v = chars[v % byte(Mod)]
				for _,ig := range ignore {
					if v == ig {
						continue nch
					}
				}
				ret[i] = v
				break nch
			}
		}
	}
	return string(ret)
}

var passes = make(PasswordStore)

func ReaderToSrc(src io.Reader) ByteSrc {
	return func() (byte, bool) {
		buf := make([]byte, 1)
		for {
			if n, err := src.Read(buf); err != nil {
				fmt.Printf("ReaderToSrc err with src=%v: %v\n", src, err)
				return 0, false
			} else if n != 0 {
				return buf[0], true
			}
		}
	}
}


// Returns a ByteSrc which turns data from an io.Reader into domain-valid
//   data. Ignores all bytes which do not conform
func Domainify(src io.Reader) ByteSrc {
	fr := ReaderToSrc(src)
	return func() (byte, bool) {
again:if d, ok := fr(); ok {
			if d, ok = back[d]; ok {
				//fmt.Println("Ret from optsrc: ",string(buf), "=>", d)
				return d, true
			}
			goto again
		}
		return 0, false
	}
}

// Todo: randomize capitilization of otp in the files
type bbuf []byte

func (b *bbuf) Append(by byte) {
	*b = append(*b, by)
}
func (b *bbuf) Read() (byte, bool) {
	a := *b
	if len(a) == 0 {
		return 0, false
	}
	ret := a[0]
	*b = a[1:]
	return ret, true
}

// Hard-coded to 2 bits for now
const (
	OtpBits = 2
	OtpLen  = (1 << OtpBits)
)

// Srcs should only return data in the domain
func JoinOtps(hash *BitBuf, srcs [OtpLen]ByteSrc) ByteSrc {
	//return func() (byte, bool) { return 0, true }
	cur := 0
	return func() (byte, bool) {
		hc, ok := hash.Next(OtpBits)
		if !ok {
			fmt.Println("Otp ran out of juice because the hash ran out of bits")
			return 0, false
		}
		cur = (cur + int(hc)) % OtpLen

		// Find a valid character
		return srcs[cur]()
	}
}

// Expects values from otp to be already in the correct form and for
//    src to only return characters in the domain (contained in the
//    back map or chars array)
// if HumanReadOutput is false:
//    dst is written values v such that 0 <= v < Mod
// else
//    dst is written values v shifted back to human readable form
func Pad(dst ByteDst, src ByteSrc, otp ByteSrc, forward bool) {
	for {
		c, ok := src()
		if !ok {
			break
		}
		oldc := c
		if c, ok = back[c]; !ok {
			panic(fmt.Sprint("src contains invalid character: ", oldc))
		}

		// Find next pad byte to use
		var pad byte
		if pad, ok = otp(); !ok {
			panic("Entropy must not decrease!")
		}

		mm := byte(Mod)
		// Double check the input is in the correct form
		if c >= mm || pad >= mm {
			panic(fmt.Sprintf("Bad input: %v or %v", c, pad))
		}

		// unbugging
		str := string([]byte{chars[pad], chars[c]})
		chr := []byte{pad, c}
		_, _ = str, chr
		
		if forward {
			c = (c + pad) % mm
		} else {
			c = (c - pad + mm) % mm
		}
		
		//fmt.Printf("Adding letters: %v; [pad, input]=%v, sum=%v (%v)\n", str, chr, c, string([]byte{chars[c]}))
		if HumanReadOutput {
			c = chars[c]
		}
		dst(c)
	}
}

type ByteSrc func() (byte, bool)
type ByteDst func(byte)

type BitBuf struct {
	src ByteSrc

	buf uint32
	// Number of bits left in buf, organized toward the right of the number
	filled uint
}

func (b *BitBuf) Next(bits uint) (uint32, bool) {
	// It's easier to support less bits at a time. I don't need more than 16 at a time so it'll be ok
	if bits > 16 {
		panic("Unsupported operation")
	}
	buf, f := b.buf, b.filled

	for f < bits {
		v, ok := b.src()
		if !ok {
			return 0, false
		}
		buf |= uint32(v) << f
		f += 8
	}
	ret := buf & ((1 << bits) - 1)
	b.buf = buf >> bits
	b.filled = f - bits
	return ret, true
}

var back = func() map[byte]byte {
	ret := make(map[byte]byte, len(chars))

	for i, v := range chars {
		ret[v] = byte(i)
	}

	return ret
}()

var Mod = len(chars)

func init() {
	if Mod > 256 {
		panic("Too many values in the supported list of characters!")
	}
}

var chars = [...]byte{
	'a',
	'b',
	'c',
	'd',
	'e',
	'f',
	'g',
	'h',
	'i',
	'j',
	'k',
	'l',
	'm',
	'n',
	'o',
	'p',
	'q',
	'r',
	's',
	't',
	'u',
	'v',
	'w',
	'x',
	'y',
	'z',
	'A',
	'B',
	'C',
	'D',
	'E',
	'F',
	'G',
	'H',
	'I',
	'J',
	'K',
	'L',
	'M',
	'N',
	'O',
	'P',
	'Q',
	'R',
	'S',
	'T',
	'U',
	'V',
	'W',
	'X',
	'Y',
	'Z',
	'`', //`// My syntax coloring is bad at doing colors with this character, this fixes it
	'~',
	'0',
	'1',
	'2',
	'3',
	'4',
	'5',
	'6',
	'7',
	'8',
	'9',
	'-',
	'=',
	'!',
	'@',
	'#',
	'$',
	'%',
	'^',
	'&',
	'*',
	'(',
	')',
	'_',
	'+',
	',',
	'.',
	'/',
	'<',
	'>',
	'?',
	';',
	'\'',
	':',
	'"', //"// My syntax coloring is bad at doing colors with this character, this fixes it
	'[',
	']',
	'\\',
	'{',
	'}',
	'|',
	' ',
}
