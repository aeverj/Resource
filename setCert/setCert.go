package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func getPENtHeaderOffset(fileBytes []byte) uint32 {
	ntHeaderOffsetBytes := fileBytes[0x3C:0x40]
	return binary.LittleEndian.Uint32(ntHeaderOffsetBytes)
}

func is32BitPE(fileBytes []byte) bool {
	ntHeaderOffset := getPENtHeaderOffset(fileBytes)
	characteristicsOffset := ntHeaderOffset + 0x16
	characteristicsBytes := fileBytes[characteristicsOffset : characteristicsOffset+2]
	characteristics := binary.LittleEndian.Uint16(characteristicsBytes)
	return characteristics&0x0100 == 0x0100
}

func getCertTableOffset(fileBytes []byte) uint32 {
	ntHeaderOffset := getPENtHeaderOffset(fileBytes)
	var certTblOffsetFromNtHeader uint32 = 0xA8
	if is32BitPE(fileBytes) {
		certTblOffsetFromNtHeader = 0x98
	}
	return ntHeaderOffset + certTblOffsetFromNtHeader
}

func extractCertificate(sourceFile string) ([]byte, error) {
	file, err := os.Open(sourceFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open source file: %w", err)
	}
	defer file.Close()

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read source file: %w", err)
	}

	peFile, err := pe.NewFile(bytes.NewReader(fileBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to parse PE file: %w", err)
	}
	defer peFile.Close()

	var signatureVirtualAddress uint32
	var signatureSize uint32

	switch op := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		signatureVirtualAddress = op.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress
		signatureSize = op.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].Size
	case *pe.OptionalHeader64:
		signatureVirtualAddress = op.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress
		signatureSize = op.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].Size
	default:
		return nil, fmt.Errorf("unsupported PE format")
	}

	if signatureVirtualAddress == 0 || signatureSize == 0 {
		return nil, fmt.Errorf("no certificate found in the source file")
	}

	return fileBytes[signatureVirtualAddress : signatureVirtualAddress+signatureSize], nil
}

func applyCertificate(targetFile, outputFile string, cert []byte) error {
	file, err := os.Open(targetFile)
	if err != nil {
		return fmt.Errorf("failed to open target file: %w", err)
	}
	defer file.Close()

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read target file: %w", err)
	}

	certTableOffset := getCertTableOffset(fileBytes)

	// Update certificate table entry
	binary.LittleEndian.PutUint32(fileBytes[certTableOffset:certTableOffset+4], uint32(len(fileBytes)))
	binary.LittleEndian.PutUint32(fileBytes[certTableOffset+4:certTableOffset+8], uint32(len(cert)))

	// Create output directory if it doesn't exist
	outputDir := filepath.Dir(outputFile)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write the modified file
	if err := os.WriteFile(outputFile, append(fileBytes, cert...), 0755); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}

func main() {
	// Define simple flag parameters
	var sourceFile string
	var targetFile string
	var outputFile string

	flag.StringVar(&sourceFile, "s", "", "Source PE file to extract certificate from")
	flag.StringVar(&targetFile, "t", "", "Target PE file to apply certificate to")
	flag.StringVar(&outputFile, "o", "", "Output file path (optional, defaults to 'signed_[targetfile]')")

	// Add usage examples
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "PE Certificate Cloning Tool\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s -s [source.exe] -t [target.exe] [-o output.exe]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Parameters:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -s signed.exe -t unsigned.exe -o result.exe\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -s signed.exe -t unsigned.exe\n", os.Args[0])
	}

	flag.Parse()

	// Check if required parameters are provided
	if sourceFile == "" || targetFile == "" {
		fmt.Println("Error: Source (-s) and target (-t) files are required")
		flag.Usage()
		return
	}

	// If output is not specified, create a default name
	if outputFile == "" {
		targetBase := filepath.Base(targetFile)
		targetDir := filepath.Dir(targetFile)
		outputFile = filepath.Join(targetDir, "signed_"+targetBase)
	}

	// Extract certificate
	cert, err := extractCertificate(sourceFile)
	if err != nil {
		fmt.Printf("Error extracting certificate: %v\n", err)
		return
	}

	fmt.Printf("Successfully extracted certificate (%d bytes) from %s\n", len(cert), sourceFile)

	// Apply certificate
	if err := applyCertificate(targetFile, outputFile, cert); err != nil {
		fmt.Printf("Error applying certificate: %v\n", err)
		return
	}

	fmt.Printf("Successfully applied certificate to %s\n", outputFile)
}
