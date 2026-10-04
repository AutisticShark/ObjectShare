package htmx

import (
	"context"
	"io"
	"net/http"
	"time"
)

// The server-wide read and write timeouts (5 minutes by default) are absolute
// budgets that net/http starts when a request's headers arrive. That is right
// for pages and API calls but cuts off a large upload or download from a slow
// connection however steadily it makes progress. For an upload the write
// deadline matters as much as the read deadline: if it is not moved, a body
// that takes longer than WriteTimeout to arrive is stored and counted, yet its
// response (the redirect and the guest owner cookie) can never be written.
//
// The proxied transfer routes therefore turn both timeouts into inactivity
// windows. While an upload is received and while storage consumes it, every
// read pushes the read and write deadlines out again; every write of a download
// pushes the write deadline out. A transfer survives as long as data keeps
// moving, the response still has a full write window once the stored upload is
// finished, and a stalled transfer still ends after the configured timeout.

// transferProgress moves a request's connection deadlines one window ahead.
type transferProgress struct {
	controller  *http.ResponseController
	read, write time.Duration
}

func (progress *transferProgress) extend() {
	now := time.Now()
	if progress.read > 0 {
		_ = progress.controller.SetReadDeadline(now.Add(progress.read))
	}
	if progress.write > 0 {
		_ = progress.controller.SetWriteDeadline(now.Add(progress.write))
	}
}

// progressBody extends the connection's deadlines before every read.
type progressBody struct {
	io.ReadCloser
	progress *transferProgress
}

func (body *progressBody) Read(buffer []byte) (int, error) {
	body.progress.extend()
	return body.ReadCloser.Read(buffer)
}

// progressReader extends the connection's deadlines while object storage reads
// an upload that has already been received.
type progressReader struct {
	io.Reader
	progress *transferProgress
}

func (reader *progressReader) Read(buffer []byte) (int, error) {
	reader.progress.extend()
	return reader.Reader.Read(buffer)
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

type transferProgressKey struct{}

// withUploadProgress keeps a slow multipart upload alive while bytes arrive and
// returns the request to use from then on. Pass the readers handed to object
// storage through uploadProgressReader so storing the upload counts as progress.
func (handler *Handler) withUploadProgress(writer http.ResponseWriter, request *http.Request) *http.Request {
	progress := &transferProgress{controller: http.NewResponseController(writer),
		read: handler.config.ReadTimeout.Duration(), write: handler.config.WriteTimeout.Duration()}
	if progress.read <= 0 && progress.write <= 0 {
		return request
	}
	request = request.WithContext(context.WithValue(request.Context(), transferProgressKey{}, progress))
	request.Body = &progressBody{ReadCloser: request.Body, progress: progress}
	return request
}

// uploadProgressReader restarts the deadlines now and on every read of reader,
// for a request prepared by withUploadProgress. Keeping the read deadline ahead
// matters too: once the body is consumed, net/http watches the connection with
// a background read, and that read timing out would cancel the request context
// in the middle of a long storage write.
func uploadProgressReader(request *http.Request, reader io.Reader) io.Reader {
	progress, ok := request.Context().Value(transferProgressKey{}).(*transferProgress)
	if !ok {
		return reader
	}
	progress.extend()
	return &progressReader{Reader: reader, progress: progress}
}

// withDownloadProgress keeps a slow proxied download alive while it is consumed.
func (handler *Handler) withDownloadProgress(writer http.ResponseWriter) http.ResponseWriter {
	if window := handler.config.WriteTimeout.Duration(); window > 0 {
		return &progressWriter{ResponseWriter: writer, controller: http.NewResponseController(writer), window: window}
	}
	return writer
}
