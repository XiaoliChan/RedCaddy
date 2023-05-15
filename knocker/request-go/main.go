package main

import (
	"net/http"
	"crypto/tls"
)

func main() {
	transCfg := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ignore expired SSL certificates
	}
  	client := &http.Client{Transport: transCfg}
  	req, _ := http.NewRequest("GET", "https://192.168.1.1:6443/b1b41dba69184f90a99b29323e8f1cf9", nil)
	req.Header.Add("user-agent", "SecurityString")
	req.Header.Add("Accept-SecurityString", "a32649a472fd435485d5e8cb3d1b34ef")
  	client.Do(req)
}
