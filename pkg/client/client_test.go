package client

import (
	"fmt"
	"log"
	"net/smtp"
	"testing"
)

func TestClient(t *testing.T) {
	//client, err := New(&Options{"http://127.0.0.1", false})
	//require.Nil(t, err, "could not create client")
	//
	//for i := 0; i < 10; i++ {
	//	fmt.Printf("URL: %s\n", client.URL())
	//}
	//for i := 0; i < 10; i++ {
	//	reflection := server.URLReflection(client.URL())
	//	fmt.Printf("reflection: %s\n", reflection)
	//}
	//
	// Connect to the remote SMTP server.
	c, err := smtp.Dial("127.0.0.1:25")
	if err != nil {
		log.Fatal(err)
	}

	// Set the sender and recipient first
	if err := c.Mail("sender@example.org"); err != nil {
		log.Fatal(err)
	}
	if err := c.Rcpt("recipient@example.net"); err != nil {
		log.Fatal(err)
	}

	// Send the email body.
	wc, err := c.Data()
	if err != nil {
		log.Fatal(err)
	}
	_, err = fmt.Fprintf(wc, "This is the email body")
	if err != nil {
		log.Fatal(err)
	}
	err = wc.Close()
	if err != nil {
		log.Fatal(err)
	}

	// Send the QUIT command and close the connection.
	err = c.Quit()
	if err != nil {
		log.Fatal(err)
	}
}
