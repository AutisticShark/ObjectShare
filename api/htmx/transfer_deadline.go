package htmx

import (
	"io"
	"net/http"
	"time"
)

// The server-wide read and write timeouts (5 minutes by default) are absolute
// budgets for a whole request, which is right for pages and API calls but cuts
// off a large upload or download from a slow connection however steadily it
// makes progress. The proxied transfer routes therefore turn them into
// inactivity windows: every read or write pushes the deadline out again, so a
// transfer survives as long as data keeps moving and a stalled one still ends
// after the configured timeout.

// progressBody extends the connection's read deadline before every read.
type progressBody struct {
	io.ReadCloser
	controller *http.ResponseController
	window     time.Duration
}

func (body *progressBody) Read(buffer []byte) (int, error) {
	_ = body.controller.SetReadDeadline(time.Now().Add(body.window))
	return body.ReadCloser.Read(buffer)
}

// progressWriter extends the connection's write deadline before every write.
type progressWriter struct {
	http.ResponseWriter
	controller *http.ResponseController
	window     time.Duration
}

func (writer *progressWriter) Write(buffer []byte) (int, error) {
	_ = writer.controller.SetWriteDeadline(time.Now().Add(writer.window))
	return writer.ResponseWriter.Write(buffer)
}

// Unwrap lets http.ResponseController reach the underlying connection.
func (writer *progressWriter) Unwrap() http.ResponseWriter { return writer.ResponseWriter }

// withUploadProgress keeps a slow multipart upload alive while bytes arrive.
func (handler *Handler) withUploadProgress(writer http.ResponseWriter, request *http.Request) {
	if window := handler.config.ReadTimeout.Duration(); window > 0 {
		request.Body = &progressBody{ReadCloser: request.Body, controller: http.NewResponseController(writer), window: window}
	}
}

// withDownloadProgress keeps a slow proxied download alive while it is consumed.
func (handler *Handler) withDownloadProgress(writer http.ResponseWriter) http.ResponseWriter {
	if window := handler.config.WriteTimeout.Duration(); window > 0 {
		return &progressWriter{ResponseWriter: writer, controller: http.NewResponseController(writer), window: window}
	}
	return writer
}
