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

// Konfigurasi Port Mapping (Ubah bagian ini sesuai kebutuhan LAN Anda!)
// Format: OnionPort -> "IP_Lokal:Port_Lokal"
var portMappings = map[int]string{
	80:    "192.168.1.10:80",    // Meneruskan akses web (Port 80) ke Web UI Dahua
	37777: "192.168.1.10:37777", // Meneruskan port TCP Stream Dahua (agar video tidak blank)
}

// loadPrivateKey membaca file rahasia Tor dan membuang 32-byte header
func loadPrivateKey(filename string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	if len(data) != 96 {
		return nil, fmt.Errorf("format atau panjang file kunci tidak valid")
	}

	// Mengambil 64 byte terakhir sebagai private key
	privKey := ed25519.PrivateKey(data[32:])
	return privKey, nil
}

// generateOnionAddress menghitung ulang alamat .onion dari public key untuk ditampilkan
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

	encoded := base32.StdEncoding.EncodeToString(addrBytes)
	return strings.ToLower(encoded)
}

// checkTarget melakukan simulasi koneksi TCP untuk memastikan target aktif
func checkTarget(address string) bool {
	timeout := 2 * time.Second
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false // Tidak bisa terhubung
	}
	if conn != nil {
		conn.Close()
		return true // Berhasil terhubung
	}
	return false
}

func main() {
	fmt.Println("Membaca private key...")

	// Baca untuk perhitungan ekstrak address di CLI
	privKey, err := loadPrivateKey("hs_ed25519_secret_key")
	if err != nil {
		log.Fatalf("Gagal mengekstrak kunci: %v", err)
	}

	// === PENDEKATAN VIRTUAL TORRC ===
	fmt.Println("Menyiapkan folder proxy portabel...")

	// 1. Buat folder temporary (sementara) yang otomatis dihapus nanti
	hsDir, err := os.MkdirTemp("", "onion_hs_*")
	if err != nil {
		log.Fatalf("Gagal membuat folder sementara: %v", err)
	}
	defer os.RemoveAll(hsDir) // Pembersihan saat aplikasi mati

	// Pastikan folder di set 0700 (aturan ketat daemon Tor)
	os.Chmod(hsDir, 0700)

	// 2. Salin file kunci utuh ke dalam folder sementara tersebut
	keyDataUtuh, err := os.ReadFile("hs_ed25519_secret_key")
	if err != nil {
		log.Fatalf("Gagal membaca file kunci lokal: %v", err)
	}
	keyPath := filepath.Join(hsDir, "hs_ed25519_secret_key")
	err = os.WriteFile(keyPath, keyDataUtuh, 0600)
	if err != nil {
		log.Fatalf("Gagal menyalin kunci ke folder sementara: %v", err)
	}

	// 3. Merangkai instruksi argument untuk Daemon Tor (Virtual Torrc)
	var args []string
	// Convert path ke slash format (menghindari error di Windows)
	cleanHsDir := filepath.ToSlash(hsDir)
	args = append(args, "--HiddenServiceDir", cleanHsDir)

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
		fmt.Println("⚠️  Tor akan tetap dijalankan, namun akses ke Onion dipastikan akan menghasilkan error ERR_SOCKS_CONNECTION_FAILED.")
		fmt.Println("⚠️  Pastikan CCTV menyala, kabel LAN terhubung, dan tidak terblokir Windows Firewall.")
		fmt.Println("-----------------------------------------------------------------------------------------")
		time.Sleep(3 * time.Second) // Memberi waktu user membaca pesan error
	}

	fmt.Println("Memulai instance Tor terintegrasi (mohon tunggu beberapa detik)...")

	// Mencari lokasi executable Tor secara otomatis
	var torExePath string
	if _, err := os.Stat("tor.exe"); err == nil {
		torExePath = "tor.exe" // Gunakan yang ada di folder yang sama (Windows)
	} else if _, err := os.Stat("tor"); err == nil {
		torExePath = "./tor" // Gunakan yang ada di folder yang sama (Linux/Mac)
	} else {
		torExePath = "" // Biarkan kosong agar library mencari di environment PATH bawaan OS
	}

	// Start daemon Tor dengan extra arguments (tanpa libtor)
	t, err := tor.Start(context.Background(), &tor.StartConf{
		ExePath:   torExePath,
		ExtraArgs: args,
	})
	if err != nil {
		fmt.Printf("\n[ERROR FATAL]\nProgram Tor tidak ditemukan!\nSilakan download Windows Expert Bundle dari https://www.torproject.org/download/tor/\nLalu ekstrak dan copy 'tor.exe' beserta semua file '.dll' ke folder project ini.\n\nDetail error: %v\n", err)
		os.Exit(1)
	}
	defer t.Close()

	// Hitung vanity address untuk ditampilkan di layar
	pubKey := privKey.Public().(ed25519.PublicKey)
	onionID := generateOnionAddress(pubKey)

	fmt.Printf("\n====================================================\n")
	fmt.Printf("   PROXY FORWARDER ONION BERHASIL BERJALAN!\n")
	fmt.Printf("   Alamat Anda: %s.onion\n", onionID)
	fmt.Printf("====================================================\n\n")

	fmt.Println("⏳ PERHATIAN: Jaringan Tor membutuhkan waktu 2 hingga 3 menit untuk mempublikasikan alamat Anda.")
	fmt.Println("⏳ Tolong TUNGGU SEBENTAR sebelum membuka alamat onion tersebut di Tor Browser...")
	fmt.Println("\nAplikasi proxy sedang berjalan. Tekan Ctrl+C untuk mematikan.")

	// Menahan agar aplikasi Golang tidak langsung keluar (berhenti)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nMematikan proxy dan membersihkan folder sementara...")
}
