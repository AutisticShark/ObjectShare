// Package invoice renders portable invoice documents entirely on the server.
package invoice

import (
	"bytes"
	_ "embed"
	"fmt"
	"strings"
	"unicode"

	"github.com/AutisticShark/ObjectShare/db"
	"github.com/go-pdf/fpdf"
	"golang.org/x/image/font/gofont/goregular"
	"golang.org/x/image/font/sfnt"
)

//go:embed fonts/NotoSansTC-Regular.ttf
var notoSansTC []byte

// PDF uses embedded fonts, fixed margins, wrapping and automatic pagination.
// Glyphs absent from the embedded font are shown as explicit Unicode code points
// so identifiers and non-Latin names are never silently dropped or misrendered.
func PDF(invoice db.Invoice, issuer string) ([]byte, error) {
	font, err := sfnt.Parse(goregular.TTF)
	if err != nil {
		return nil, err
	}
	fontBytes := goregular.TTF
	var probe sfnt.Buffer
	for _, r := range issuer + invoice.Name + invoice.Description + invoice.Email {
		glyph, _ := font.GlyphIndex(&probe, r)
		if glyph == 0 && r <= 0xffff && !unicode.IsControl(r) {
			fontBytes = notoSansTC
			font, err = sfnt.Parse(fontBytes)
			if err != nil {
				return nil, err
			}
			break
		}
	}
	text := func(value string) string {
		var out strings.Builder
		var buffer sfnt.Buffer
		for _, r := range value {
			if unicode.IsControl(r) {
				if r == '\n' {
					out.WriteRune(r)
				} else {
					out.WriteByte(' ')
				}
				continue
			}
			glyph, _ := font.GlyphIndex(&buffer, r)
			if glyph == 0 || r > 0xffff {
				fmt.Fprintf(&out, "[U+%04X]", r)
			} else {
				out.WriteRune(r)
			}
		}
		return out.String()
	}
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(20, 20, 20)
	pdf.SetAutoPageBreak(true, 22)
	pdf.AddUTF8FontFromBytes("Go", "", fontBytes)
	pdf.SetTitle("Invoice "+invoice.ID, true)
	pdf.SetAuthor(text(issuer), true)
	pdf.SetCreationDate(invoice.CreatedAt)
	pdf.SetCatalogSort(true)
	pdf.SetFooterFunc(func() {
		pdf.SetY(-15)
		pdf.SetFont("Go", "", 9)
		pdf.SetTextColor(100, 110, 125)
		pdf.CellFormat(0, 6, fmt.Sprintf("Invoice %s | Page %d", invoice.ID, pdf.PageNo()), "", 0, "C", false, 0, "")
	})
	pdf.AddPage()
	pdf.SetTextColor(32, 48, 74)
	pdf.SetFont("Go", "", 22)
	pdf.MultiCell(170, 10, text(issuer), "", "L", false)
	pdf.SetFont("Go", "", 16)
	pdf.MultiCell(170, 9, "INVOICE - "+strings.ToUpper(invoice.Status), "", "L", false)
	pdf.Ln(5)
	pdf.SetFont("Go", "", 10)
	for _, line := range []string{"Invoice number: " + invoice.ID, "Issued: " + invoice.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"), "Billed to: " + invoice.Email} {
		pdf.MultiCell(170, 6, text(line), "", "L", false)
	}
	pdf.Ln(8)
	pdf.SetFillColor(238, 242, 248)
	pdf.SetFont("Go", "", 12)
	pdf.MultiCell(170, 9, "Purchase (quantity: 1)", "", "L", true)
	pdf.Ln(3)
	pdf.MultiCell(170, 7, text(invoice.Name), "", "L", false)
	pdf.SetFont("Go", "", 10)
	pdf.MultiCell(170, 6, text(invoice.Description), "", "L", false)
	if invoice.Kind == "plan" {
		pdf.MultiCell(170, 6, fmt.Sprintf("Access duration: %d days | Price: %d account credits", invoice.DurationDays, invoice.Credits), "", "L", false)
	}
	pdf.Ln(7)
	pdf.SetFont("Go", "", 15)
	pdf.MultiCell(170, 9, fmt.Sprintf("Total: %s %d.%02d", invoice.Currency, invoice.AmountMinor/100, invoice.AmountMinor%100), "", "R", false)
	pdf.Ln(8)
	pdf.SetFont("Go", "", 10)
	if invoice.PaidAt != nil {
		pdf.MultiCell(170, 6, "Paid: "+invoice.PaidAt.UTC().Format("2006-01-02 15:04 UTC"), "", "L", false)
		pdf.MultiCell(170, 6, text("Payment method: "+invoice.Gateway+"\nPayment reference: "+invoice.PaymentID), "", "L", false)
		pdf.Ln(5)
		pdf.MultiCell(170, 6, "Thank you. Your payment is confirmed.", "", "L", false)
	} else {
		pdf.MultiCell(170, 6, "Unpaid. Payment window ends: "+invoice.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC"), "", "L", false)
		pdf.MultiCell(170, 6, "Pay this invoice from your account on the website. Access starts only after payment is confirmed.", "", "L", false)
	}
	var output bytes.Buffer
	err = pdf.Output(&output)
	return output.Bytes(), err
}
