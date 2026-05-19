package integration

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"strings"

	"golang.org/x/net/publicsuffix"
)

type Client struct {
	c         *http.Client
	baseURL   string
	Discovery DiscoveryResponse
}

func NewClient(baseURL string) *Client {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		panic(err)
	}

	client := &http.Client{
		Jar: jar,
	}
	return &Client{
		c:       client,
		baseURL: baseURL,
	}
}

func (c *Client) Reset() {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		panic(err)
	}

	c.c = &http.Client{
		Jar: jar,
	}
}

func (c *Client) NewRequest(method, path string) *ClientRequest {
	url := path
	if !strings.HasPrefix("http", path) {
		url = c.baseURL + path
	}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Form = make(map[string][]string)

	return &ClientRequest{
		c: c.c,
		r: req,
	}
}

type ClientRequest struct {
	c *http.Client
	r *http.Request
	q map[string]string
}

func (r *ClientRequest) SetBasicAuth(username, password string) *ClientRequest {
	r.r.SetBasicAuth(username, password)
	return r
}

func (r *ClientRequest) SetHeader(key, value string) *ClientRequest {
	r.r.Header.Set(key, value)
	return r
}

func (r *ClientRequest) AddQuery(key, value string) *ClientRequest {
	if r.q == nil {
		r.q = make(map[string]string)
	}

	r.q[key] = value
	return r
}

func (r *ClientRequest) AddForm(key, value string) *ClientRequest {
	r.r.Form.Add(key, value)
	return r
}

func (r *ClientRequest) Send() (*ClientResponse, error) {
	if len(r.r.Form) > 0 {
		r.r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.r.Body = io.NopCloser(io.MultiReader(strings.NewReader(r.r.Form.Encode())))
	}

	if r.q != nil && len(r.q) > 0 {
		q := r.r.URL.Query()
		for k, v := range r.q {
			q.Add(k, v)
		}
		r.r.URL.RawQuery = q.Encode()

	}

	resp, err := r.c.Do(r.r)
	return &ClientResponse{r: resp}, err
}

type ClientResponse struct {
	r *http.Response
}

func (r *ClientResponse) URL() string {
	return r.r.Request.URL.String()
}

func (r *ClientResponse) FullURLPath() string {
	path := r.r.Request.URL.Path
	if r.r.Request.URL.RawQuery != "" {
		path += "?" + r.r.Request.URL.RawQuery
	}

	return path
}

func (r *ClientResponse) StatusCode() int {
	return r.r.StatusCode
}

func (r *ClientResponse) Header(key string) string {
	return r.r.Header.Get(key)
}

func (r *ClientResponse) BodyAsString() string {
	body, err := io.ReadAll(r.r.Body)
	if err != nil {
		log.Fatal(err)
	}

	return string(body)
}

func (r *ClientResponse) BodyAsJSON(v interface{}) error {
	body, err := io.ReadAll(r.r.Body)
	if err != nil {
		log.Fatal(err)
	}
	return json.Unmarshal(body, v)
}

func (r *ClientResponse) GetReturnURL() string {
	return r.r.Request.URL.Query()["return_url"][0]
}

func (r *ClientResponse) Close() {
	r.r.Body.Close()
}
