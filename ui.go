package main
// Woo final-hour hackiness!

import (
	"strconv"
	"os"
	"fmt"
	"bufio"
	"github.com/howeyc/gopass"
	"os/exec"
	"math/big"
)

func ClearScreen() {
    cmd := exec.Command("cmd", "/c", "cls")
    cmd.Stdout = os.Stdout
    cmd.Run()
}

type Out func(...interface{})

func wr(s...interface{}) {
	for _,v := range s {
		fmt.Print(v)
	}
	fmt.Println()
}

func Load(pass, salt []byte) {
	if f, err := os.Open("pass.wd"); err != nil {
		fmt.Println("Error opening existing data:", err)
		fmt.Println("    (ignore if first run)")
		pause()
	} else {
		passes.Load(pass, salt, ReaderToSrc(f))
		f.Close()
	}
}
func Save(pass, salt []byte) {
	if f, err := os.Create("pass.wd"); err != nil {
		fmt.Println("Error opening file to write to:", err)
		pause()
	} else {
		passes.Store(pass, salt,
			func(b byte) {
				buf := []byte{b}
				if n, err := f.Write(buf); n != 1 {
					panic(fmt.Sprint("Error writing save file: ", err))
				}
			})
		f.Close()
	}
}

func pause(s...string) {
	for  _,v := range s {
		fmt.Println(v)
	}
	in("Press enter...")
}

const Debug = false

func getPasswd() {
	ClearScreen()
	wr("Retrieve existing password\n")
	key := ins("Name of password: ")
	if v, ok := passes[key]; ok {
		setClipboard(v)
		pause("\nCopied to clipboard\nDon't forget to copy something else after pasting\n")
		return
	}
	if Debug {
		fmt.Println("Debug dump: ", passes)
	}
	pause("Key not found in database")
}
func newPasswd() {
	ClearScreen()
	wr("Make new password\n")
	key := ins("Name of password: ")
	strlen := ins("Password length: ")
	ig := in("Characters to not include: ")
	
	ilen, err := strconv.Atoi(strlen)
	if err != nil {
		pause("That wasn't a number")
		return
	}
	
	passes[key] = NewPass(ilen, ig)
	
	if Debug {
		fmt.Println("Debug dump:\n\t", passes)
	}
	
	a, b := big.NewInt(int64(Mod-len(ig))), big.NewInt(int64(ilen))
	var z big.Int
	z.Exp(a, b, nil)
	fmt.Printf("Made new password; Approx chance of guessing = 1/%s\n\n", z.String())
	pause("note that changes have not been saved.")
}
func lstPasswd() {
	ClearScreen()
	v := ins("You sure you want to list all the keys of your passwords? [N/y]")
	if v != "Y" && v != "y" {
		return
	}
	fmt.Println()
	for k := range passes {
		fmt.Println("\t", k)
	}
	pause()
}
// Converts to string
func ins(p string) string {
	return string(in(p))
}
func in(p string) []byte {
	fmt.Print(p)
	return gopass.GetPasswd()
}

func main() {
	pass := in("Password: ")
	salt := in("Salt: ")

	Load(pass, salt)
	for {
		ClearScreen()
		wr("Choose something:\n")
		wr("\t0: Get existing password")
		wr("\t1: Create new/overwrite existing password")
		wr("\t2: List password names")
		wr("\tSave: Save to disk (permanent!)")
		
		switch ins("\nChoice: ") {
			case "0": getPasswd()
			case "1": newPasswd()
			case "2": lstPasswd()
			case "Save": Save(pass, salt)
				pause("Saved")
			default:
				fmt.Println("Unknown option")
				pause()
		}
	}
}


func getInput() func()string {
	sc := bufio.NewScanner(os.Stdin)
	return func() string {
		// TODO: errors
		sc.Scan()
		return sc.Text()
	}
}
