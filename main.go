package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	xj "github.com/basgys/goxml2json"
	"github.com/gorilla/mux"
)

type config struct { // nolint
	awsRegion        string // AWS_REGION
	awsAPIEndpoint   string // AWS_API_ENDPOINT
	s3Bucket         string // AWS_S3_BUCKET
	s3KeyPrefix      string // AWS_S3_KEY_PREFIX
	httpCacheControl string // HTTP_CACHE_CONTROL (max-age=86400, no-cache ...)
	httpExpires      string // HTTP_EXPIRES (Thu, 01 Dec 1994 16:00:00 GMT ...)
	basicAuthUser    string // BASIC_AUTH_USER
	basicAuthPass    string // BASIC_AUTH_PASS
	port             string // APP_PORT
	host             string // APP_HOST
	accessLog        bool   // ACCESS_LOG
	stripPath        string // STRIP_PATH
	contentEncoding  bool   // CONTENT_ENCODING
	corsAllowOrigin  string // CORS_ALLOW_ORIGIN
	corsAllowMethods string // CORS_ALLOW_METHODS
	corsAllowHeaders string // CORS_ALLOW_HEADERS
	corsMaxAge       int64  // CORS_MAX_AGE
	healthCheckPath  string // HEALTHCHECK_PATH
	jwtTokenExpiry   string
	jwtSecret        string
}

var (
	version = "0.0.1"
	date    string
	c       *config
)

func main() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	c = configFromEnvironmentVariables()
	m := mux.NewRouter()

	m.HandleFunc("/--version", func(w http.ResponseWriter, r *http.Request) {
		if len(version) > 0 && len(date) > 0 {
			if _, err := fmt.Fprintf(w, "version: %s (built at %s)\n", version, date); err != nil {
				log.Printf("write-error: %+v", err)
			}
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}).Methods(http.MethodGet)

	m.Handle("/auth", authorize(authHandler())).Methods(http.MethodPost)
	m.Handle("/upload", authorize(uploadHandler())).Methods(http.MethodPost)

	if os.Getenv("SECURE_DOWNLOAD") != "" {
		m.PathPrefix("/").Handler(authorize(wrapper(awss3))).Methods(http.MethodGet)
	} else {
		m.PathPrefix("/").Handler(wrapper(awss3)).Methods(http.MethodGet)
	}

	// Listen & Serve
	addr := net.JoinHostPort(c.host, c.port)
	log.Printf("[service] listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, m))
}

func configFromEnvironmentVariables() *config {
	if len(os.Getenv("AWS_ACCESS_KEY_ID")) == 0 {
		log.Print("Not defined environment variable: AWS_ACCESS_KEY_ID")
	}

	if len(os.Getenv("AWS_SECRET_ACCESS_KEY")) == 0 {
		log.Print("Not defined environment variable: AWS_SECRET_ACCESS_KEY")
	}

	if len(os.Getenv("AWS_S3_BUCKET")) == 0 {
		log.Fatal("Missing required environment variable: AWS_S3_BUCKET")
	}

	region := os.Getenv("AWS_REGION")
	if len(region) == 0 {
		region = os.Getenv("AWS_DEFAULT_REGION")
		if len(region) == 0 {
			region = "us-east-1"
		}
	}
	endpoint := os.Getenv("AWS_API_ENDPOINT")
	if len(endpoint) == 0 {
		endpoint = ""
	}
	port := os.Getenv("APP_PORT")
	if len(port) == 0 {
		port = "80"
	}
	accessLog := false
	if b, err := strconv.ParseBool(os.Getenv("ACCESS_LOG")); err == nil {
		accessLog = b
	}
	contentEncoding := false
	if b, err := strconv.ParseBool(os.Getenv("CONTENT_ENCODING")); err == nil {
		contentEncoding = b
	}
	corsMaxAge := int64(600)
	if i, err := strconv.ParseInt(os.Getenv("CORS_MAX_AGE"), 10, 64); err == nil {
		corsMaxAge = i
	}
	jwtTokenExpiry := os.Getenv("JWT_TOKEN_EXPIRY")
	if len(jwtTokenExpiry) == 0 {
		jwtTokenExpiry = "60"
	}
	jwtSecret := os.Getenv("JWT_SECRET")
	if len(jwtSecret) == 0 {
		jwtSecret = "secret"
	}
	conf := &config{
		awsRegion:        region,
		awsAPIEndpoint:   endpoint,
		s3Bucket:         os.Getenv("AWS_S3_BUCKET"),
		s3KeyPrefix:      os.Getenv("AWS_S3_KEY_PREFIX"),
		httpCacheControl: os.Getenv("HTTP_CACHE_CONTROL"),
		httpExpires:      os.Getenv("HTTP_EXPIRES"),
		basicAuthUser:    os.Getenv("BASIC_AUTH_USER"),
		basicAuthPass:    os.Getenv("BASIC_AUTH_PASS"),
		port:             port,
		host:             os.Getenv("APP_HOST"),
		accessLog:        accessLog,
		stripPath:        os.Getenv("STRIP_PATH"),
		contentEncoding:  contentEncoding,
		corsAllowOrigin:  os.Getenv("CORS_ALLOW_ORIGIN"),
		corsAllowMethods: os.Getenv("CORS_ALLOW_METHODS"),
		corsAllowHeaders: os.Getenv("CORS_ALLOW_HEADERS"),
		corsMaxAge:       corsMaxAge,
		healthCheckPath:  os.Getenv("HEALTHCHECK_PATH"),
		jwtTokenExpiry:   jwtTokenExpiry,
		jwtSecret:        jwtSecret,
	}
	// Proxy
	log.Printf("[config] Proxy to %v", conf.s3Bucket)
	log.Printf("[config] AWS Region: %v", conf.awsRegion)

	// Basic authentication
	if (len(conf.basicAuthUser) > 0) && (len(conf.basicAuthPass) > 0) {
		log.Printf("[config] Basic authentication: %s", conf.basicAuthUser)
	}
	// CORS
	if (len(conf.corsAllowOrigin) > 0) && (conf.corsMaxAge > 0) {
		log.Printf("[config] CORS enabled: %s", conf.corsAllowOrigin)
	}

	return conf
}

type custom struct {
	io.Writer
	http.ResponseWriter
	status int
}

func (r *custom) Write(b []byte) (int, error) {
	if r.Header().Get("Content-Type") == "" {
		r.Header().Set("Content-Type", http.DetectContentType(b))
	}
	return r.Writer.Write(b)
}

func (r *custom) WriteHeader(status int) {
	r.ResponseWriter.WriteHeader(status)
	r.status = status
}

func uploadHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var b bytes.Buffer
		if _, err := r.Body.Read(b.Bytes()); err != nil {
			http.Error(w, "error processing request", http.StatusBadRequest)
			return
		}

		jt, ok := r.Context().Value("jwt").(*Token)
		if !ok {
			http.Error(w, "jwt token not found in handler context", http.StatusBadRequest)
			return
		}
		project := r.Header.Get("X-Project-Name")

		if err := r.ParseMultipartForm(1024); nil != err {
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		svc := s3.New(awsSession())
		var out []string

		for _, fHeaders := range r.MultipartForm.File {
			for _, hdr := range fHeaders {
				infile, err := hdr.Open()
				if err != nil {
					http.Error(w, fmt.Sprintf("input-read-error: %+v", err), http.StatusBadRequest)
				}

				key := filepath.Join(c.s3KeyPrefix, project, jt.Username, hdr.Filename)
				log.Printf("uploading %s", key)
				if _, err := s3Upload(svc, c.s3Bucket, key, infile); err != nil {
					http.Error(w, fmt.Sprintf("upload-error: %+v", err), http.StatusInternalServerError)
					return
				} else {
					out = append(out, key)
				}
			}
		}

		resp, _ := json.Marshal(&out)

		if _, err := w.Write(resp); err != nil {
			log.Printf("response-write-error: %+v", err)
		}
	}
}

func authHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			http.Error(w, "Authorization not passed", http.StatusUnauthorized)
			return
		}

		expiry, err := strconv.ParseInt(c.jwtTokenExpiry, 10, 64)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		token, err := createToken(username, password, expiry)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if _, err := w.Write([]byte(token)); err != nil {
			http.Error(w, fmt.Sprintf("write-response-error: %+v", err), http.StatusBadRequest)
			return
		}
	}
}

func wrapper(f func(w http.ResponseWriter, r *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (len(c.corsAllowOrigin) > 0) && (len(c.corsAllowMethods) > 0) && (len(c.corsAllowHeaders) > 0) && (c.corsMaxAge > 0) {
			w.Header().Set("Access-Control-Allow-Origin", c.corsAllowOrigin)
			w.Header().Set("Access-Control-Allow-Methods", c.corsAllowMethods)
			w.Header().Set("Access-Control-Allow-Headers", c.corsAllowHeaders)
			w.Header().Set("Access-Control-Max-Age", strconv.FormatInt(c.corsMaxAge, 10))
		}

		if (len(c.basicAuthUser) > 0) && (len(c.basicAuthPass) > 0) && !basicAuth(r) && !isHealthCheckPath(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="REALM"`)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		f(w, r)
	})
}

func basicAuth(r *http.Request) bool {
	if username, password, ok := r.BasicAuth(); ok {
		return username == c.basicAuthUser &&
			password == c.basicAuthPass
	}
	return false
}

func isHealthCheckPath(r *http.Request) bool {
	path := r.URL.Path
	if len(c.healthCheckPath) > 0 && path == c.healthCheckPath {
		return true
	}
	return false
}

func header(r *http.Request, key string) (string, bool) {
	if r.Header == nil {
		return "", false
	}
	if candidate := r.Header[key]; len(candidate) > 0 {
		return candidate[0], true
	}
	return "", false
}

func awss3(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	rangeHeader := r.Header.Get("Range")

	// Strip the prefix, if it's present.
	if len(c.stripPath) > 0 {
		path = strings.TrimPrefix(path, c.stripPath)
	}

	// If there is a health check path defined, and if this path matches it,
	// then return 200 OK and return.
	// Note: we want to apply the health check *after* the prefix is stripped.
	if len(c.healthCheckPath) > 0 && path == c.healthCheckPath {
		w.WriteHeader(http.StatusOK)
		return
	}

	obj, err := s3get(c.s3Bucket, c.s3KeyPrefix+path, rangeHeader)
	if err != nil {
		code, message := awsError(err)
		http.Error(w, message, code)
		return
	}
	setHeadersFromAwsResponse(w, obj)
	body := io.Reader(obj.Body)

	// NOTE: By default when no key is specified this function will return all
	// the objects present in the given bucket in XML format. Convert this
	// XML output to JSON format.
	if c.s3KeyPrefix+path == "/" {
		body, err = xj.Convert(body)
		if err != nil {
			log.Printf("Error converting XML to JSON")
			panic(err)
		}
	}

	if _, err := io.Copy(w, body); err != nil {
		log.Printf("io-copy-error: %+v", err)
	}
}

func setHeadersFromAwsResponse(w http.ResponseWriter, obj *s3.GetObjectOutput) {
	// Cache-Control
	if len(c.httpCacheControl) > 0 {
		setStrHeader(w, "Cache-Control", &c.httpCacheControl)
	} else {
		setStrHeader(w, "Cache-Control", obj.CacheControl)
	}

	// Expires
	if len(c.httpExpires) > 0 {
		setStrHeader(w, "Expires", &c.httpExpires)
	} else {
		setStrHeader(w, "Expires", obj.Expires)
	}

	setStrHeader(w, "Content-Disposition", obj.ContentDisposition)
	setStrHeader(w, "Content-Encoding", obj.ContentEncoding)
	setStrHeader(w, "Content-Language", obj.ContentLanguage)
	setIntHeader(w, "Content-Length", obj.ContentLength)
	setStrHeader(w, "Content-Range", obj.ContentRange)
	setStrHeader(w, "Content-Type", obj.ContentType)
	setStrHeader(w, "ETag", obj.ETag)
	setTimeHeader(w, "Last-Modified", obj.LastModified)

	httpStatus := determineHTTPStatus(obj)

	w.WriteHeader(httpStatus)
}

func determineHTTPStatus(obj *s3.GetObjectOutput) int {
	httpStatus := http.StatusOK

	contentRangeIsGiven := obj.ContentRange != nil && len(*obj.ContentRange) > 0

	if contentRangeIsGiven {
		httpStatus = http.StatusPartialContent

		if totalFileSizeEqualToContentRange(obj) {
			httpStatus = http.StatusOK
		}

	}
	return httpStatus
}

func totalFileSizeEqualToContentRange(obj *s3.GetObjectOutput) bool {
	totalSizeIsEqualToContentRange := false
	if totalSize, err := strconv.ParseInt(getFileSizeAsString(obj), 10, 64); err == nil {
		if totalSize == (*obj.ContentLength) {
			totalSizeIsEqualToContentRange = true
		}
	}
	return totalSizeIsEqualToContentRange
}

/**
See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Range
*/
func getFileSizeAsString(obj *s3.GetObjectOutput) string {
	s := strings.Split(*obj.ContentRange, "/")
	totalSizeString := s[1]
	totalSizeString = strings.TrimSpace(totalSizeString)
	return totalSizeString
}

func s3get(backet, key, rangeHeader string) (*s3.GetObjectOutput, error) {
	var rangeHeaderAwsString *string

	if len(rangeHeader) > 0 {
		rangeHeaderAwsString = aws.String(rangeHeader)
	}

	req := &s3.GetObjectInput{
		Bucket: aws.String(backet),
		Key:    aws.String(key),
		Range:  rangeHeaderAwsString,
	}

	return s3.New(awsSession()).GetObject(req)
}

func s3Upload(svc *s3.S3, bucket, key string, data io.ReadSeeker) (*s3.PutObjectOutput, error) {
	req := &s3.PutObjectInput{
		Key:    aws.String(key),
		Bucket: aws.String(bucket),
		Body:   data,
	}

	return svc.PutObject(req)
}

func awsSession() *session.Session {
	config := &aws.Config{
		Region: aws.String(c.awsRegion),
	}
	if len(c.awsAPIEndpoint) > 0 {
		config.Endpoint = aws.String(c.awsAPIEndpoint)
		config.S3ForcePathStyle = aws.Bool(true)
	}
	return session.Must(session.NewSession(config))
}

func setStrHeader(w http.ResponseWriter, key string, value *string) {
	if value != nil && len(*value) > 0 {
		w.Header().Add(key, *value)
	}
}

func setIntHeader(w http.ResponseWriter, key string, value *int64) {
	if value != nil && *value > 0 {
		w.Header().Add(key, strconv.FormatInt(*value, 10))
	}
}

func setTimeHeader(w http.ResponseWriter, key string, value *time.Time) {
	if value != nil && !reflect.DeepEqual(*value, time.Time{}) {
		w.Header().Add(key, value.UTC().Format(http.TimeFormat))
	}
}

func awsError(err error) (int, string) {
	if aerr, ok := err.(awserr.Error); ok {
		switch aerr.Code() {
		case s3.ErrCodeNoSuchBucket, s3.ErrCodeNoSuchKey:
			return http.StatusNotFound, aerr.Error()
		}
		return http.StatusInternalServerError, aerr.Error()
	}
	return http.StatusInternalServerError, err.Error()
}
