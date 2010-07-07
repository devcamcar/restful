package restful

import (
    "bytes"
    "crypto/rand"
    "crypto/tls"
    "encoding/base64"
    "fmt"
    "http"
    "io"
    "log"
    "net"
    "os"
    "strings"
    "time"
)

type readCloser struct {
    io.Reader
    io.Closer
}

type closer struct {
    io.Reader
}

func (closer) Close() os.Error { return nil }


type RestClient struct {
    Endpoint    string
    Proxy       string
    UserInfo    string
    // TODO(devcamcar): UserAgent string
}

func (client *RestClient) SubmitRequest(url, method string, headers, params map[string]string) (*http.Response, os.Error) {
    var request  *http.Request
    var response *http.Response
    var body      string
    var err       os.Error

    if headers == nil {
        headers = make(map[string]string)
        headers["Content-Type"] = "text/plain"
    }
    
    method = strings.ToUpper(method)
    
    rawurl := strings.Join([]string { client.Endpoint, url }, "")

    if params != nil {
        if method == "GET" {
            rawurl += "?" + urlEncode(&params)
        } else if method == "PUT" || method == "POST" {
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            body = urlEncode(&params)
        }
    }

    log.Stdout("URL: " + rawurl)
    log.Stdout("Body: " + body)
    
     if len(client.UserInfo) > 0 {
        enc := base64.URLEncoding
        encoded := make([]byte, enc.EncodedLen(len(client.UserInfo)))
        enc.Encode(encoded, []byte(client.UserInfo))
        headers["Authorization"] = "Basic " + string(encoded)
    }
    
    if request, err = prepareHttpRequest(rawurl, method, &headers); err != nil {
        return nil, err
    }
    
    if len(body) > 0 {
        request.ContentLength = int64(len(body))
        request.Body = closer{bytes.NewBufferString(body)}
    }
    
    dump, _ := http.DumpRequest(request, true)
    log.Stdout(string(dump))
    
    if response, err = client.sendHttpRequest(request); err != nil {
        return nil, err
    }

    return response, nil
}

func urlEncode(data *map[string]string) string {
    args := ""

    for key, value := range *data {
        if len(args) > 0 {
            args += "&"
        }
        
        args += fmt.Sprintf("%s=%s", key, value)
    }
    
    return args
}

func prepareHttpRequest(rawurl, method string, headers *map[string]string) (*http.Request, os.Error) {
    var request  http.Request
    var url     *http.URL
    var err      os.Error
    
    if url, err = http.ParseURL(rawurl); err != nil {
        return nil, err
    }
    
    request.Header = *headers
    request.Method = method
    request.URL = url
    
    return &request, nil
}

func (client *RestClient) sendHttpRequest(req *http.Request) (resp *http.Response, err os.Error) {
    var conn *http.ClientConn;

    if conn, err = makeConnection(req.URL, client.Proxy); err != nil {
        return nil, err
    }
    
    err = conn.Write(req)

    if protoerr, ok := err.(*http.ProtocolError); ok && protoerr == http.ErrPersistEOF {
        // the connection has been closed in an HTTP keepalive sense
        conn, _ = makeConnection(req.URL, client.Proxy)
        err = conn.Write(req)
    } else if err == io.ErrUnexpectedEOF {
        // the underlying connection has been closed "gracefully"
        conn, _ = makeConnection(req.URL, client.Proxy)
        err = conn.Write(req)
    }

    if err != nil {
        return nil, err
    }

    resp, err = conn.Read()

    if protoerr, ok := err.(*http.ProtocolError); ok && protoerr == http.ErrPersistEOF {
        // the remote requested that this be the last request serviced
        conn, _ = makeConnection(req.URL, client.Proxy)
    } else if err != nil {
        return nil, err
    }

    log.Stdout(resp.Proto + " " + resp.Status);

    if len(resp.Header) > 0 {
        for key, val := range resp.Header {
            fmt.Println("\x1b[1m" + key + "\x1b[22m: " + val)
        }
        fmt.Println()
    }

    return 
}

func makeConnection(url *http.URL, proxy string) (*http.ClientConn, os.Error) {
    var tcp     net.Conn
    var useSSL  bool
    var conn    *http.ClientConn
    var err     os.Error

    // Determine host and port.
    addr := url.Host;

    if !hasPort(addr) {
        if url.Scheme == "https" {
            useSSL = true
            addr += ":443"
        } else {
            addr += ":80"
        }
    }
    
    if len(proxy) > 0 {
        proxy_url, _ := http.ParseURL(proxy)
        tcp, err = net.Dial("tcp", "", proxy_url.Host)
    } else {
        tcp, err = net.Dial("tcp", "", addr)
    }

    if err != nil {
        return nil, err
    }

    if useSSL {
        cf := &tls.Config{Rand: rand.Reader, Time: time.Nanoseconds}
        ssl := tls.Client(tcp, cf)
        conn = http.NewClientConn(ssl, nil)

        if len(proxy) > 0 {
            tcp.Write([]byte("CONNECT " + addr + " HTTP/1.0\r\n\r\n"))
            b := make([]byte, 1024)
            tcp.Read(b)
        }
    } else {
        conn = http.NewClientConn(tcp, nil)
    }

    return conn, nil
}

// Given a string of the form "host", "host:port", or "[ipv6::address]:port",
// return true if the string includes a port.
func hasPort(s string) bool     { return strings.LastIndex(s, ":") > strings.LastIndex(s, "]") }
