package main

import (
	"os"
	"io"
	"fmt"
	"net"
	"time"
	"errors"
	"strings"
	"strconv"
)

const DEBUG = false 
const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

var server string

func Log(message string) error {
	service := "inVirScan"
	loglevel := "info"
	logfilelocation := "/logs/inVirScan.log"

        file, err := os.OpenFile(logfilelocation, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
                return errors.New("Failed to open log file for writing: " + err.Error())
        }
        defer file.Close()

        current_time := time.Now().Local()
        t := current_time.Format("Jan 02 2006 03:04:05")
        _, err = file.WriteString(loglevel + " | " + t + " | " + service + " | " + message + "\n")

        if err != nil {
                return errors.New("Failed to write to log file: " + err.Error())
        }

        return nil
}

func virscan() error {
	var conn net.Conn
	var err error
	icapService := "avscan"

	conn, err = net.DialTimeout("tcp", server, 5 * time.Second)
	if err != nil {
		return err
	}

	defer conn.Close()

	file := []byte(eicar)

	length := len(file)
	strlen := strconv.Itoa(length)
	hexval := fmt.Sprintf("%x", length)

	conn.Write([]byte("RESPMOD icap://127.0.0.1:1344/" + icapService + " ICAP/1.0\r\n"))
	conn.Write([]byte("Host: 127.0.0.1:1344\r\n"))
	conn.Write([]byte("User-Agent: CAC ICAP Client/1.1\r\n"))
	conn.Write([]byte("Allow: 204\r\n"))
	conn.Write([]byte("Connection: close\r\n"))
	conn.Write([]byte("Encapsulated: res-hdr=0, res-body=" + strlen + "\r\n"))
	conn.Write([]byte("\r\n"))
	conn.Write([]byte("Content-Length: " + strlen + "\r\n"))
	conn.Write([]byte("\r\n"))
	conn.Write([]byte(hexval + "\r\n"))
	conn.Write(file)
	conn.Write([]byte("\r\n"))
	conn.Write([]byte("0; ieof\r\n\r\n"))

	tmp := make([]byte, 256)
	output := ""

	for {
		_, err := conn.Read(tmp)
		if err != nil {
			if err != io.EOF {
			}
			break
		}

		output += string(tmp)
	}

	xthreat := ""
	infected := false
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "X-Infection-Found") {
			parts := strings.Split(line, ";")
			sthreat := strings.Split(parts[2], "=")
			xthreat = sthreat[1]
			infected = true
		}
	}

	_ = xthreat

	if ! infected {
		return err
	}

	return nil

}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: " + os.Args[0] + " <server_or_vip>")
		os.Exit(0)
	}

	server = os.Args[1]

	if ! strings.Contains(server, ":") {
		server += ":1344"
	}

	conn, err := net.DialTimeout("tcp", server, 5 * time.Second)
	if err != nil {
		os.Exit(2)
	}
	conn.Close()

	err = virscan()
	if err != nil {
		os.Exit(2)
	}

	os.Exit(0)
}
