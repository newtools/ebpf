package ebpf

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// Errors returned by the implementation
var (
	ErrNotSupported = errors.New("ebpf: not supported by kernel")
)

const (
	// Number of bytes to pad the output buffer for BPF_PROG_TEST_RUN.
	// This is currently the maximum of spare space allocated for SKB
	// and XDP programs, and equal to XDP_PACKET_HEADROOM + NET_IP_ALIGN.
	outputPad = 256 + 2
)

// ProgramSpec is an interface that can initialize a new Program
type ProgramSpec interface {
	ProgType() ProgType
	Instructions() *Instructions
	License() string
	KernelVersion() uint32
}

// Program represents a Program file descriptor
type Program int

// NewProgram creates a new Program
func NewProgram(progType ProgType, instructions *Instructions, license string, kernelVersion uint32) (Program, error) {
	if instructions == nil {
		return -1, fmt.Errorf("instructions cannot be nil")
	}
	var cInstructions []bpfInstruction
	for _, ins := range *instructions {
		inss := ins.getCStructs()
		for _, ins2 := range inss {
			cInstructions = append(cInstructions, ins2)
		}
	}
	insCount := uint32(len(cInstructions))
	if insCount > MaxBPFInstructions {
		return -1, fmt.Errorf("max instructions, %d, exceeded", MaxBPFInstructions)
	}
	lic := []byte(license)
	logs := make([]byte, LogBufSize)
	fd, e := bpfCall(_ProgLoad, unsafe.Pointer(&progCreateAttr{
		progType:     progType,
		insCount:     insCount,
		instructions: newPtr(unsafe.Pointer(&cInstructions[0])),
		license:      newPtr(unsafe.Pointer(&lic[0])),
		logLevel:     1,
		logSize:      LogBufSize,
		logBuf:       newPtr(unsafe.Pointer(&logs[0])),
	}), 48)
	if e != 0 {
		if logs[0] != 0 {
			return -1, fmt.Errorf("%s:\n\t%s", bpfErrNo(e), strings.Replace(string(logs), "\n", "\n\t", -1))
		}
		return -1, bpfErrNo(e)
	}
	return Program(fd), nil
}

// NewProgramFromSpec creates a new Program from the ProgramSpec interface
func NewProgramFromSpec(spec ProgramSpec) (Program, error) {
	return NewProgram(spec.ProgType(), spec.Instructions(), spec.License(), spec.KernelVersion())
}

// GetFd gets the file descriptor value of the Program
func (bpf Program) GetFd() int {
	return int(bpf)
}

// Pin persists the Program past the lifetime of the process that created it
func (bpf Program) Pin(fileName string) error {
	return pinObject(fileName, uint32(bpf))
}

// Close unloads the program from the kernel.
func (bpf Program) Close() error {
	return syscall.Close(int(bpf))
}

// LoadProgram loads a Program from a BPF file
func LoadProgram(fileName string) (Program, error) {
	ptr, err := getObject(fileName)
	return Program(ptr), err
}
