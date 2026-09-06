package invoice

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/db"
)

func TestPDFInvoice(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	invoice := db.Invoice{ID: "11111111-1111-4111-8111-111111111111", Kind: "plan", Name: "Plus - café - 進階方案", Description: strings.Repeat("Secure storage and sharing. ", 15), Email: "buyer@example.com", Credits: 25, AmountMinor: 2500, Currency: "USD", DurationDays: 30, Status: "paid", Gateway: "stripe", PaymentID: "pi_verified", CreatedAt: now, PaidAt: &now}
	data, err := PDF(invoice, "ObjectShare")
	if err != nil || !bytes.HasPrefix(data, []byte("%PDF-")) || !bytes.Contains(data, []byte("%%EOF")) {
		t.Fatalf("invalid PDF: %v", err)
	}
	if path := os.Getenv("OBJECTSHARE_TEST_INVOICE_PDF"); path != "" {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	invoice.Name = strings.Repeat("漢字 😀", 80)
	invoice.Description = strings.Repeat("long text ", 1000)
	if _, err = PDF(invoice, "Brand\r\nwith controls\x00"); err != nil {
		t.Fatal(err)
	}
}
