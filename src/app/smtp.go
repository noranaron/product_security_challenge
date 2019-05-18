package app

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"
)

type Mail struct {
	SenderId string
	ToIds    []string
	Subject  string
	Body     string
}

type SmtpServer struct {
	Host     string
	Port     string
	Username string
	Password string
	UseTLS   bool
}

func (s *SmtpServer) ServerName() string {
	return s.Host + ":" + s.Port
}

func (mail *Mail) BuildMessage() string {
	message := ""
	message += fmt.Sprintf("From: %s\r\n", mail.SenderId)
	if len(mail.ToIds) > 0 {
		message += fmt.Sprintf("To: %s\r\n", strings.Join(mail.ToIds, ";"))
	}

	message += fmt.Sprintf("Subject: %s\r\n", mail.Subject)
	message += "\r\n" + mail.Body

	return message
}

func SendEmail(mail *Mail) error {
	messageBody := mail.BuildMessage()

	var client *smtp.Client
	if Options.SMTP_SERVER.UseTLS {
		tlsconfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         Options.SMTP_SERVER.Host,
		}

		conn, err := tls.Dial("tcp", Options.SMTP_SERVER.ServerName(), tlsconfig)
		if err != nil {
			return err
		}
		defer conn.Close()

		client, err = smtp.NewClient(conn, Options.SMTP_SERVER.Host)
		if err != nil {
			return err
		}
	} else {
		var err error
		client, err = smtp.Dial(Options.SMTP_SERVER.ServerName())
		if err != nil {
			return err
		}
	}
	defer client.Close()

	auth := smtp.PlainAuth("", Options.SMTP_SERVER.Username, Options.SMTP_SERVER.Password, Options.SMTP_SERVER.Host)
	if err := client.Auth(auth); err != nil {
		return err
	}

	if err := client.Mail(mail.SenderId); err != nil {
		return err
	}
	for _, k := range mail.ToIds {
		if err := client.Rcpt(k); err != nil {
			return err
		}
	}

	w, err := client.Data()
	if err != nil {
		return err
	}

	_, err = w.Write([]byte(messageBody))
	if err != nil {
		return err
	}

	err = w.Close()
	if err != nil {
		return err
	}

	client.Quit()
	return nil
}