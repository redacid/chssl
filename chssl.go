package main

import (
	"crypto/tls"
	//"flag"
	"fmt"
	"os"
	"path/filepath"
	"net"
	"time"
	"encoding/json"
)

//var runAs = filepath.Base(os.Args[0])
const STATE_OK = 0
const STATE_WARNING = 1
const STATE_CRITICAL = 2
//const STATE_UNKNOWN = 3 //not used
var state int=STATE_OK
var output string=""

type Config struct {
	Servers  []Server
	Global
}
type Server struct {
	Host	string `json:"host"`
	Port	string `json:"port"`
	Domain	string `json:"domain"`
	SkipVerify bool `json:"skipVerify"`
}
type Global struct {
	Timeout int `json:"timeout"`
	WarnDays int `json:"warnDays"`
	CritDays int `json:"critDays"`
}

// Usage is what is run if the right parameters are not met upon startup.
/*func Usage() {
	// To embed the bot user and password comment the line above and uncomment the line below
	fmt.Printf("Usage: %v \n", runAs)
	flag.PrintDefaults()
}*/

func main() {

	appdir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		fmt.Printf("Could not open config.json , %v.\n\n",err)
		state = STATE_CRITICAL;
		os.Exit(state)
	}

	//Парсим файл конфигурации
	file, _ := os.Open(appdir+"/config.json")
	decoder := json.NewDecoder(file)
	Config := new(Config)
	err = decoder.Decode(&Config)
	if err != nil {
		fmt.Printf("ERROR: %v \n", err)
		os.Exit(STATE_CRITICAL)
	}
	defer file.Close()
	//fmt.Printf("Timeout: %d \n", Config.Timeout)
	//fmt.Printf("WarnDays: %d \n", Config.WarnDays)
	//fmt.Printf("CritDays: %d \n", Config.CritDays)

	var ipAddress string
	for _, Server := range Config.Servers {
		//fmt.Printf("Host: %v \n", Server.Host)
		//fmt.Printf("Port: %v \n", Server.Port)
		//output = output + "Domain: " + Server.Domain + "\n"
		output = output + "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
		//fmt.Printf("Domain: %v \n", Server.Domain)

		ip, err := net.LookupHost(Server.Host)
		if err != nil {
			ipAddress = ipAddress + ":" + Server.Port
			output = output + "CRITICAL Could not resolve host name " + Server.Host + "\n"
			//fmt.Printf("Could not resolve host name, %v.\n\n",Server.Host)
			switch state {
			case STATE_OK:
				state = STATE_WARNING;
			case STATE_WARNING:
				state = STATE_WARNING;
			case STATE_CRITICAL:
				state = STATE_CRITICAL;
			}
			//os.Exit(state)
		}
		ipAddress = ip[0] + ":" + Server.Port

		ipConn,err:=net.DialTimeout("tcp",ipAddress,time.Duration(Config.Timeout)*time.Millisecond)
		if err != nil {
			output = output + "CRITICAL Could not connect to " + ipAddress + " " + Server.Host + " " + err.Error() + "\n"
			//fmt.Printf("Could not connect to %v - %v\n %v",ipAddress,Server.Domain,err)
			switch state {
			case STATE_OK:
				state = STATE_WARNING;
			case STATE_WARNING:
				state = STATE_WARNING;
			case STATE_CRITICAL:
				state = STATE_CRITICAL;
			}
			//os.Exit(state)
		} else {
			defer ipConn.Close()
		}
		// Configure tls to look at domainName
		tlsconfig := tls.Config{ServerName: Server.Domain,InsecureSkipVerify:Server.SkipVerify}
		// Connect to tls
		conn:= tls.Client(ipConn, &tlsconfig)
		defer conn.Close()
		// Handshake with TLS to get cert
		hsErr := conn.Handshake()
		if hsErr != nil {
			//fmt.Printf("Client connected to: %v\n", conn.RemoteAddr())
			output = output + "CRITICAL Cert Failed for " + ipAddress + " " + Server.Domain + " " + hsErr.Error() + "\n"
			//fmt.Printf("Cert Failed for %v - %v\n %v\n", ipAddress, Server.Domain, hsErr)
			switch state {
			case STATE_OK:
				state = STATE_CRITICAL;
			case STATE_WARNING:
				state = STATE_CRITICAL;
			case STATE_CRITICAL:
				state = STATE_CRITICAL;
			}
			//os.Exit(state)
		} else {
			//fmt.Printf("Client connected to: %v\n", conn.RemoteAddr())
			output = output + "OK Cert Checks " + Server.Domain + " is valid\n"
			//fmt.Printf("Cert Checks OK\n")
			//os.Exit(state)
		}
		connstate := conn.ConnectionState()

		for _, v := range connstate.PeerCertificates {
			timeNow := time.Now()
			if timeNow.AddDate(0,0,Config.CritDays).After(v.NotAfter) {
				output = output + "CRITICAL Cert " + Server.Domain + " expired soon\n"
				//fmt.Printf("CRITICAL Cert expired \n")
				output = output + "CN: " + v.Subject.CommonName + " Expired " + v.NotAfter.Format("2006-01-02 15:04:05") + "\n"
				//fmt.Printf("CN:%v To: %v\n", v.Subject.CommonName, v.NotAfter)
				//fmt.Printf("CN:%v From: %v To: %v\n", v.Subject.CommonName, v.NotBefore, v.NotAfter)
				switch state {
				case STATE_OK:
					state = STATE_CRITICAL;
				case STATE_WARNING:
					state = STATE_CRITICAL;
				case STATE_CRITICAL:
					state = STATE_CRITICAL;
				}
				//os.Exit(state)
			} else if timeNow.AddDate(0,0,Config.WarnDays).After(v.NotAfter) {
				output = output + "WARNING Cert " + Server.Domain + " expired soon\n"
				//fmt.Printf("WARNING Cert expired \n")
				output = output + "CN: " + v.Subject.CommonName + " Expired " + v.NotAfter.Format("2006-01-02 15:04:05") + "\n"
				//fmt.Printf("CN:%v To: %v\n", v.Subject.CommonName, v.NotAfter)
				//fmt.Printf("CN:%v From: %v To: %v\n", v.Subject.CommonName, v.NotBefore, v.NotAfter)
				switch state {
				case STATE_OK:
					state = STATE_WARNING;
				case STATE_WARNING:
					state = STATE_WARNING;
				case STATE_CRITICAL:
					state = STATE_CRITICAL;
				}

				//os.Exit(state)
			} else {
				//fmt.Printf("OK Cert not expired \n")
				output = output + "CN: " + v.Subject.CommonName + " Expired " + v.NotAfter.Format("2006-01-02 15:04:05") + "\n"
				//fmt.Printf("CN:%v To: %v\n", v.Subject.CommonName, v.NotAfter)
				//fmt.Printf("CN:%v From: %v To: %v\n", v.Subject.CommonName, v.NotBefore, v.NotAfter)
				//os.Exit(state)
			}

		}

	}

	switch state {
	case STATE_OK:
		fmt.Print("OK Certs of all domains is valid\n")
	case STATE_WARNING:
		fmt.Print("WARNING Expired soon cert(s) exists\n")
	case STATE_CRITICAL:
		fmt.Print("CRITICAL Expired soon cert(s) exists\n")
	}

	fmt.Printf("%v",output)
	//fmt.Printf("EXITSTATE: %d\n", state)
	os.Exit(state)

}