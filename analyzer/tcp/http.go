package tcp

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/utils"
)

var _ analyzer.TCPAnalyzer = (*HTTPAnalyzer)(nil)

type HTTPAnalyzer struct{}

func (a *HTTPAnalyzer) Name() string {
	return "http"
}

func (a *HTTPAnalyzer) Limit() int {
	return 8192
}

func (a *HTTPAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
	return newHTTPStream(logger)
}

type httpStream struct {
	logger analyzer.Logger

	reqBuf     *utils.ByteBuffer
	reqMap     analyzer.PropMap
	reqUpdated bool
	reqLSM     *utils.LinearStateMachine
	reqDone    bool

	respBuf     *utils.ByteBuffer
	respMap     analyzer.PropMap
	respUpdated bool
	respLSM     *utils.LinearStateMachine
	respDone    bool
}

func newHTTPStream(logger analyzer.Logger) *httpStream {
	s := &httpStream{logger: logger, reqBuf: &utils.ByteBuffer{}, respBuf: &utils.ByteBuffer{}}
	s.reqLSM = utils.NewLinearStateMachine(
		s.parseRequestLine,
		s.parseRequestHeaders,
	)
	s.respLSM = utils.NewLinearStateMachine(
		s.parseResponseLine,
		s.parseResponseHeaders,
	)
	return s
}

func (s *httpStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, d bool) {
	if skip != 0 {
		return nil, true
	}
	if len(data) == 0 {
		return nil, false
	}
	var update *analyzer.PropUpdate
	var cancelled bool
	if rev {
		s.respBuf.Append(data)
		s.respUpdated = false
		cancelled, s.respDone = s.respLSM.Run()
		if s.respUpdated {
			update = &analyzer.PropUpdate{
				Type: analyzer.PropUpdateMerge,
				M:    analyzer.PropMap{"resp": s.respMap},
			}
			s.respUpdated = false
		}
	} else {
		s.reqBuf.Append(data)
		s.reqUpdated = false
		cancelled, s.reqDone = s.reqLSM.Run()
		if s.reqUpdated {
			update = &analyzer.PropUpdate{
				Type: analyzer.PropUpdateMerge,
				M:    analyzer.PropMap{"req": s.reqMap},
			}
			s.reqUpdated = false
		}
	}
	return update, cancelled || (s.reqDone && s.respDone)
}

func (s *httpStream) parseRequestLine() utils.LSMAction {
	// Find the end of the request line
	line, ok := s.reqBuf.GetUntil([]byte("\r\n"), true, true)
	if !ok {
		// No end of line yet, but maybe we just need more data
		return utils.LSMActionPause
	}
	fields := strings.Fields(string(line[:len(line)-2])) // Strip \r\n
	if len(fields) != 3 {
		// Invalid request line
		return utils.LSMActionCancel
	}
	method := fields[0]
	path := fields[1]
	version := fields[2]
	if !strings.HasPrefix(version, "HTTP/") {
		// Invalid version
		return utils.LSMActionCancel
	}
	s.reqMap = analyzer.PropMap{
		"method":  method,
		"path":    path,
		"version": version,
	}
	s.reqUpdated = true
	return utils.LSMActionNext
}

func (s *httpStream) parseResponseLine() utils.LSMAction {
	// Find the end of the response line
	line, ok := s.respBuf.GetUntil([]byte("\r\n"), true, true)
	if !ok {
		// No end of line yet, but maybe we just need more data
		return utils.LSMActionPause
	}
	fields := strings.Fields(string(line[:len(line)-2])) // Strip \r\n
	if len(fields) < 2 {
		// Invalid response line
		return utils.LSMActionCancel
	}
	version := fields[0]
	status, _ := strconv.Atoi(fields[1])
	if !strings.HasPrefix(version, "HTTP/") || status == 0 {
		// Invalid version
		return utils.LSMActionCancel
	}
	s.respMap = analyzer.PropMap{
		"version": version,
		"status":  status,
	}
	s.respUpdated = true
	return utils.LSMActionNext
}

func (s *httpStream) parseHeaders(buf *utils.ByteBuffer) (utils.LSMAction, analyzer.PropMap) {
	// Find the end of headers
	headers, ok := buf.GetUntil([]byte("\r\n\r\n"), true, true)
	if !ok {
		// No end of headers yet, but maybe we just need more data
		return utils.LSMActionPause, nil
	}
	headers = headers[:len(headers)-4] // Strip \r\n\r\n
	headerMap := make(analyzer.PropMap)
	for _, line := range bytes.Split(headers, []byte("\r\n")) {
		fields := bytes.SplitN(line, []byte(":"), 2)
		if len(fields) != 2 {
			// Invalid header
			return utils.LSMActionCancel, nil
		}
		key := string(bytes.TrimSpace(fields[0]))
		value := string(bytes.TrimSpace(fields[1]))
		// Normalize header keys to lowercase
		headerMap[strings.ToLower(key)] = value
	}
	return utils.LSMActionNext, headerMap
}

func (s *httpStream) parseRequestHeaders() utils.LSMAction {
	action, headerMap := s.parseHeaders(s.reqBuf)
	if action == utils.LSMActionNext {
		s.reqMap["headers"] = headerMap
		s.reqUpdated = true
	}
	return action
}

func (s *httpStream) parseResponseHeaders() utils.LSMAction {
	action, headerMap := s.parseHeaders(s.respBuf)
	if action == utils.LSMActionNext {
		s.respMap["headers"] = headerMap
		s.respUpdated = true
	}
	return action
}

func (s *httpStream) Close(limited bool) *analyzer.PropUpdate {
	s.reqBuf.Reset()
	s.respBuf.Reset()
	s.reqMap = nil
	s.respMap = nil
	return nil
}
