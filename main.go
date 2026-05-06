package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base32"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cretz/bine/tor"
	"golang.org/x/crypto/sha3"
)

// torLogWriter adalah custom logger untuk mencegat dan menganalisa log internal Tor
type torLogWriter struct{}

func (w *torLogWriter) Write(p []byte) (n int, err error) {
	msg := string(p)

	// Abaikan warning bawaan Windows yang tidak penting agar layar tidak penuh
	if strings.Contains(msg, "is relative and will resolve to") || strings.Contains(msg, "Read line: 250") {
		return len(p), nil
	}

	// Tampilkan log aslinya ke layar dengan prefix [TOR]
	fmt.Print("[TOR DEBUG] ", msg)

	// Deteksi event krusial (disesuaikan dengan format output terbaru)
	if strings.Contains(msg, "BOOTSTRAP PROGRESS=100") || strings.Contains(msg, "Bootstrapped 100%") {
		fmt.Println("\n======================================================================")
		fmt.Println(" ✅ [SUCCESS] KONEKSI TOR UTAMA BERHASIL (BOOTSTRAP 100%)")
		fmt.Println("======================================================================")
	} else if strings.Contains(msg, "Uploaded rendezvous descriptor") {
		fmt.Println("\n======================================================================")
		fmt.Println(" 🚀 [LIVE STATUS] DESCRIPTOR ONION BERHASIL DI-UPLOAD KE JARINGAN GLOBAL!")
		fmt.Println(" 🌐 ALAMAT ONION ANDA SEKARANG SUDAH BISA DIAKSES DI TOR BROWSER.")
		fmt.Println("======================================================================")
	} else if strings.Contains(msg, "Failed to load") {
		fmt.Println("\n ❌ [ERROR] Tor mendeteksi masalah pada Kunci atau Konfigurasi!")
	}

	return len(p), nil
}

// Konfigurasi Port Mapping (Ubah bagian ini sesuai kebutuhan LAN Anda!)
var portMappings = map[int]string{
	80:    "192.168.1.10:80",    // Meneruskan akses web (Port 80) ke Web UI Dahua
	443:   "192.168.1.10:443",   // Meneruskan HTTPS (jika Dahua melakukan redirect otomatis)
	37777: "192.168.1.10:37777", // Meneruskan port TCP Stream Dahua (agar video tidak blank)
}

func loadPrivateKey(filename string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if len(data) != 96 {
		return nil, fmt.Errorf("format atau panjang file kunci tidak valid")
	}
	return ed25519.PrivateKey(data[32:]), nil
}

func generateOnionAddress(pubKey ed25519.PublicKey) string {
	version := []byte{0x03}
	prefix := []byte(".onion checksum")

	var checksumData []byte
	checksumData = append(checksumData, prefix...)
	checksumData = append(checksumData, pubKey...)
	checksumData = append(checksumData, version...)

	hasher := sha3.New256()
	hasher.Write(checksumData)
	checksumFull := hasher.Sum(nil)
	checksum := checksumFull[:2]

	var addrBytes []byte
	addrBytes = append(addrBytes, pubKey...)
	addrBytes = append(addrBytes, checksum...)
	addrBytes = append(addrBytes, version...)

	return strings.ToLower(base32.StdEncoding.EncodeToString(addrBytes))
}

func checkTarget(address string) bool {
	timeout := 2 * time.Second
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	if conn != nil {
		conn.Close()
		return true
	}
	return false
}

func main() {
	fmt.Println("Membaca private key...")

	privKey, err := loadPrivateKey("hs_ed25519_secret_key")
	if err != nil {
		log.Fatalf("Gagal mengekstrak kunci: %v", err)
	}

	fmt.Println("Menyiapkan folder proxy portabel...")

	hsDir, err := os.MkdirTemp("", "onion_hs_dir_*")
	if err != nil {
		log.Fatalf("Gagal membuat folder sementara: %v", err)
	}
	defer os.RemoveAll(hsDir)

	torDataDir, err := os.MkdirTemp("", "tor_data_dir_*")
	if err != nil {
		log.Fatalf("Gagal membuat folder data Tor: %v", err)
	}
	defer os.RemoveAll(torDataDir)

	os.Chmod(hsDir, 0700)
	os.Chmod(torDataDir, 0700)

	keyDataUtuh, err := os.ReadFile("hs_ed25519_secret_key")
	if err != nil {
		log.Fatalf("Gagal membaca file kunci lokal: %v", err)
	}
	keyPath := filepath.Join(hsDir, "hs_ed25519_secret_key")
	err = os.WriteFile(keyPath, keyDataUtuh, 0600)
	if err != nil {
		log.Fatalf("Gagal menyalin kunci ke folder sementara: %v", err)
	}

	var args []string
	cleanHsDir := filepath.ToSlash(hsDir)
	args = append(args, "--HiddenServiceDir", cleanHsDir)

	// Memaksa Tor untuk menampilkan log [notice] meskipun bine menyuntikkan --hush
	args = append(args, "--Log", "notice stdout")

	fmt.Println("\n=== DIAGNOSTIK KONEKSI LOKAL ===")
	hasError := false
	for onionPort, targetAddr := range portMappings {
		portArg := fmt.Sprintf("%d %s", onionPort, targetAddr)
		args = append(args, "--HiddenServicePort", portArg)

		fmt.Printf("[Config] Onion Port %d ---> Target %s\n", onionPort, targetAddr)
		fmt.Printf("         Mengecek akses... ")

		if checkTarget(targetAddr) {
			fmt.Println("OK! (Terhubung)")
		} else {
			fmt.Println("GAGAL! (Koneksi Ditolak / Timeout)")
			hasError = true
		}
	}
	fmt.Println("================================\n")

	if hasError {
		fmt.Println("⚠️  PERINGATAN: Satu atau lebih target tidak bisa dihubungi dari komputer ini.")
		time.Sleep(3 * time.Second)
	}

	var torExePath string
	if _, err := os.Stat("tor.exe"); err == nil {
		torExePath = "tor.exe"
	} else if _, err := os.Stat("tor"); err == nil {
		torExePath = "./tor"
	} else {
		torExePath = ""
	}

	debugLogger := &torLogWriter{}
	ctx := context.Background()

	t, err := tor.Start(ctx, &tor.StartConf{
		ExePath:     torExePath,
		DataDir:     torDataDir,
		ExtraArgs:   args,
		DebugWriter: debugLogger,
	})
	if err != nil {
		fmt.Printf("\n[ERROR FATAL]\nProgram Tor gagal memulai!\nPastikan Anda sudah mematikan proses 'tor.exe' yang nyangkut di Task Manager.\nAtau jalankan: taskkill /F /IM tor.exe\n\nDetail error: %v\n", err)
		os.Exit(1)
	}
	defer t.Close()

	fmt.Println("\n[SISTEM] Menghidupkan jaringan Tor dan memulai proses Bootstrap...")
	err = t.EnableNetwork(ctx, true)
	if err != nil {
		log.Fatalf("Gagal menghidupkan jaringan Tor: %v", err)
	}

	pubKey := privKey.Public().(ed25519.PublicKey)
	onionID := generateOnionAddress(pubKey)

	fmt.Printf("\n====================================================\n")
	fmt.Printf("   PROXY FORWARDER ONION BERHASIL BERJALAN!\n")
	fmt.Printf("   Alamat Anda: %s.onion\n", onionID)
	fmt.Printf("====================================================\n\n")

	fmt.Println("⏳ PERHATIAN: Jaringan Tor membutuhkan waktu 2 hingga 3 menit untuk mempublikasikan alamat Anda.")
	fmt.Println("⏳ Tolong PERHATIKAN LOG DEBUG di atas. Tunggu sampai muncul pesan 'DESCRIPTOR BERHASIL DI-UPLOAD'...")
	fmt.Println("\nAplikasi proxy sedang berjalan. Tekan Ctrl+C untuk mematikan.\n")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nMematikan proxy dan membersihkan folder sementara...")
}
