package main

import (
	"fmt"
	"math"
	"os"
	"time"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/newtools/ebpf"
)

/*
struct newtools_ebpf_test {
    int id;
    short val16;
    short val16_2;
    char name[8];
    long lid;
};
*/
import "C"

func TestCGoGetFromKernel() error {
	var fromKernel C.struct_newtools_ebpf_test
	fromKernel.id = C.int(1234)
	fromKernel.lid = C.long(1234)
	fromKernel.name[0] = C.char('a')
	fromKernel.name[1] = C.char('b')
	fromKernel.name[2] = C.char(0)
	fromKernel.val16 = C.short(4321)
	fromKernel.val16_2 = C.short(8765)

	arr, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  C.sizeof_struct_newtools_ebpf_test,
		MaxEntries: 500000,
	})
	if err != nil {
		panic(err)
	}

	if err := arr.Put(uint64(0), fromKernel); err != nil {
		panic(err)
	}

	var value C.struct_newtools_ebpf_test
	if _, err := arr.GetBytes(uint64(0), unsafe.Pointer(&value)); err != nil {
		panic(err)
	}

	if errors.Cause(err) == unix.ENOENT {
		panic("value not found")
	}
	if fromKernel.id != value.id {
		panic("id not matching")
	}
	if fromKernel.name[1] != value.name[1] {
		panic("name[1] not matching")
	}
	if fromKernel.val16 != value.val16 {
		panic("val16 not matching")
	}
	if fromKernel.val16_2 != value.val16_2 {
		panic("val16_2 not matching")
	}
	if fromKernel.lid != value.lid {
		panic("lid not matching")
	}

	/* bench */
	for i := 0; i < 500000; i++ {
		fromKernel.lid = C.long(i)
		if err := arr.Put(uint64(i), fromKernel); err != nil {
			panic(err)
		}
	}

	t := time.Now()
	for i := 0; i < 500000; i++ {
		if _, err := arr.GetBytes(uint64(i), unsafe.Pointer(&value)); err != nil {
			panic(err)
		}
	}
	fmt.Println("time run pointer ", time.Now().Sub(t))

	t = time.Now()
	for i := 0; i < 500000; i++ {
		var b []byte
		if b, err = arr.GetBytes(uint64(i)); err != nil {
			panic(err)
		}
		_ = b
	}
	fmt.Println("time run []byte ", time.Now().Sub(t))

	return nil
}

func main() {
	err := unix.Setrlimit(8, &unix.Rlimit{
		Cur: math.MaxUint64,
		Max: math.MaxUint64,
	})
	if err != nil {
		fmt.Println("WARNING: Failed to adjust rlimit, tests may fail")
	}

	if err := TestCGoGetFromKernel(); err != nil {
		panic(err)
	} else {
		fmt.Println("TestCGoGetFromKernel() : OK")
		os.Exit(0)
	}
	os.Exit(1)
}
