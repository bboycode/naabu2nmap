package cmd

import "time"

type NaabuResult struct {
	Host      string    `json:"host"`
	IP        string    `json:"ip"`
	Timestamp time.Time `json:"timestamp"`
	Port      int       `json:"port"`
	Protocol  string    `json:"protocol"`
	TLS       bool      `json:"tls"`
}
