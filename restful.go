package main //restful

import (
	"bytes";
    "bufio";
	"container/vector";
	"crypto/rand";
	"crypto/tls";
    "encoding/base64";
	"fmt";
	"http";
	"io";
	"io/ioutil";
	"net";
	"os";
	"strconv";
	"strings";
	"time";
)

type RestClient struct {
	host    string
	proxy   string
	useSSL  bool
}

func (client *RestClient) SubmitRequest(url, method, userinfo string, headers, params *map[string][string]) (*http.HttpResponse, os.Error) {
    var request  *http.Request;
    var response *http.Response;
    var err       os.Error;

    rawurl := client.makeRawUrl(url, params)
    
    fmt.Printf("URL: %s\n", rawurl);
    
     if len(userinfo) > 0 {
        enc := base64.URLEncoding
        encoded := make([]byte, enc.EncodedLen(len(info)))
        enc.Encode(encoded, []byte(info))
        if headers == nil {
            headers = make(map[string]string)
        }
        headers["Authorization"] = "Basic " + string(encoded)
    }
    
    if request, err = client.prepareHttpRequest(rawurl, method, headers); err != nil {
        return nil, err;
    }
    
    /*if api.verbose {
        dump, _ := http.DumpRequest(request, true);
        fmt.Printf(string(dump));
    }*/
    
    if response, err = sendHttpRequest(request); err != nil {
        return nil, err;
    }

    return response, nil;
}

func (rest *RestRequest) prepareHttpRequest(rawurl, method, headers *map[string][string]) (*http.Request, os.Error) {
    var request  http.Request;
    var url     *http.URL;
    var err      os.Error;
    
    if url, err = http.ParseURL(rawurl); err != nil {
        return nil, err;
    }
    
    request.Header = headers
    request.Method = method;
    request.URL = url;

    return &request, nil;
}

func (client *RestClient) makeConnection(url *http.URL) (*http.ClientConn, os.Error) {
	var tcp     net.Conn
    var conn    *http.ClientConn
	var err     os.Error

	if len(client.proxy) > 0 {
		proxy_url, _ := http.ParseURL(client.proxy)
		tcp, err = net.Dial("tcp", "", proxy_url.Host)
	} else {
		tcp, err = net.Dial("tcp", "", addr)
	}

	if err != nil {
		return nil, err
	}

    // Determine host and port.
    addr := url.Host;
    if !hasPort(addr) {
        if url.Scheme == "https" {
            client.useSSL = true
            addr += ":443"
        }
        else {
            addr += ":80"
        }
    }

	if client.useSSL {
		cf := &tls.Config{Rand: rand.Reader, Time: time.Nanoseconds}
		ssl := tls.Client(tcp, cf)
		conn = http.NewClientConn(ssl, nil)

		if len(proxy) > 0 {
			tcp.Write([]byte("CONNECT " + host + " HTTP/1.0\r\n\r\n"))
			b := make([]byte, 1024)
			tcp.Read(b)
		}
	} else {
		conn = http.NewClientConn(tcp, nil)
	}
	
	return conn, nil
}

func (client *RestClient) makeRawUrl(url string, params *map[string]string) string {
    return strings.Join([]string { client.host, url, makeQueryString(params) }, "");
}

func makeQueryString(data map[string]string) string {
    args := "";
    sep  := "?";

    for key, value := range data {
        if len(args) > 0 {
            sep = "&";
        }
        
        args += fmt.Sprintf("%s%s=%s", sep, key, value);
    }
    
    return args; 
}

func sendHttpRequest(request *http.Request) (response *http.Response, err os.Error) {
    fmt.Printf("host: %s", host)
    
    conn, err := makeConnection(request.URL)
    
    if err != nil {
        return nil, err
    }

    err = req.Write(conn)
    
    if err != nil {
        conn.Close()
        return nil, err
    }

    reader := bufio.NewReader(conn)
    
    resp, err = http.ReadResponse(reader, req.Method)
    if err != nil {
        conn.Close()
        return nil, err
    }

    resp.Body = readClose{resp.Body, conn}

    return
}

// Given a string of the form "host", "host:port", or "[ipv6::address]:port",
// return true if the string includes a port.
func hasPort(s string) bool     { return strings.LastIndex(s, ":") > strings.LastIndex(s, "]") }

