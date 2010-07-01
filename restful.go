package restful

import (
    "bufio"
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

// Used in Send to implement io.ReadCloser by bundling together the
// io.BufReader through which we read the response, and the underlying
// network connection.
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
    var request  *http.Request;
    var response *http.Response;
    var body      string;
    var err       os.Error;

    if headers == nil {
        headers = make(map[string]string);
        headers["Content-Type"] = "text/plain";
    }
    
    method = strings.ToUpper(method);
    
    rawurl := strings.Join([]string { client.Endpoint, url }, "");

    if params != nil {
        if method == "GET" {
            rawurl += "?" + urlEncode(&params);
        } else if method == "PUT" || method == "POST" {
            headers["Content-Type"] = "application/x-www-form-urlencoded";
            body = urlEncode(&params);
        }
    }

    log.Stdout("URL: " + rawurl);
    log.Stdout("Body: " + body)
    
     if len(client.UserInfo) > 0 {
        enc := base64.URLEncoding
        encoded := make([]byte, enc.EncodedLen(len(client.UserInfo)))
        enc.Encode(encoded, []byte(client.UserInfo))
        headers["Authorization"] = "Basic " + string(encoded)
    }
    
    if request, err = prepareHttpRequest(rawurl, method, &headers); err != nil {
        return nil, err;
    }
    
    if len(body) > 0 {
        request.Body = closer{bytes.NewBufferString(body)}
    }
    
    dump, _ := http.DumpRequest(request, true);
    log.Stdout(string(dump));
    
    if response, err = client.sendHttpRequest(request); err != nil {
        return nil, err;
    }

    return response, nil;
}

func urlEncode(data *map[string]string) string {
    args := "";

    for key, value := range *data {
        if len(args) > 0 {
            args += "&";
        }
        
        args += fmt.Sprintf("%s=%s", key, value);
    }
    
    return args; 
}

func prepareHttpRequest(rawurl, method string, headers *map[string]string) (*http.Request, os.Error) {
    var request  http.Request;
    var url     *http.URL;
    var err      os.Error;
    
    if url, err = http.ParseURL(rawurl); err != nil {
        return nil, err;
    }
    
    request.Header = *headers;
    request.Method = method;
    request.URL = url;

    return &request, nil;
}

func (client *RestClient) sendHttpRequest(req *http.Request) (resp *http.Response, err os.Error) {
    conn, err := makeConnection(req.URL, client.Proxy)
    
    if err != nil {
        return nil, err
    }
    
    if err = req.Write(conn); err != nil {
        conn.Close()
        return
    }

    reader := bufio.NewReader(conn)
    
    if resp, err = http.ReadResponse(reader, req.Method); err != nil {
        conn.Close()
        return
    }

    resp.Body = readCloser{resp.Body, conn}

    return
}

func makeConnection(url *http.URL, proxy string) (net.Conn, os.Error) {
	var tcp     net.Conn
	var useSSL  bool
    var conn    net.Conn
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
		//ssl := tls.Client(tcp, cf)
		//conn = http.NewClientConn(ssl, nil)
		conn = tls.Client(tcp, cf)

		if len(proxy) > 0 {
			tcp.Write([]byte("CONNECT " + addr + " HTTP/1.0\r\n\r\n"))
			b := make([]byte, 1024)
			tcp.Read(b)
		}
	} else {
		conn = tcp
	}
	
	return conn, nil
}

// Given a string of the form "host", "host:port", or "[ipv6::address]:port",
// return true if the string includes a port.
func hasPort(s string) bool     { return strings.LastIndex(s, ":") > strings.LastIndex(s, "]") }
