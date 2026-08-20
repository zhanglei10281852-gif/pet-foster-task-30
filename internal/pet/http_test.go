package pet

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPFrontendContract(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	server := httptest.NewServer(NewHandler(service))
	defer server.Close()
	client := server.Client()
	body := bytes.NewBufferString(`{"username":"testuser","password":"user123"}`)
	response, err := client.Post(server.URL+"/api/user/login", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var login struct {
		Code int `json:"code"`
		Data struct {
			Token string `json:"token"`
			User  User   `json:"user"`
		} `json:"data"`
	}
	if err := json.NewDecoder(response.Body).Decode(&login); err != nil {
		t.Fatal(err)
	}
	if login.Code != 200 || login.Data.Token == "" || login.Data.User.Role != RoleUser {
		t.Fatalf("login=%+v", login)
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/api/pet/list?pageNum=1&pageSize=10", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+login.Data.Token)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var page struct {
		Code int       `json:"code"`
		Data Page[Pet] `json:"data"`
	}
	if err := json.NewDecoder(response.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}
	if page.Code != 200 || page.Data.List == nil {
		t.Fatalf("page=%+v", page)
	}
}

func TestHTTPRejectsUnauthenticatedRequests(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	request := httptest.NewRequest(http.MethodGet, "/api/order/list", nil)
	response := httptest.NewRecorder()
	NewHandler(service).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestHTTPRegistrationCreatesLoginReadyUser(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	server := httptest.NewServer(NewHandler(service))
	defer server.Close()

	response, err := server.Client().Post(server.URL+"/api/user/register", "application/json", bytes.NewBufferString(`{"username":"newowner","password":"owner123","phone":"13800000000","email":"owner@example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("register status=%d", response.StatusCode)
	}

	loginResponse, err := server.Client().Post(server.URL+"/api/user/login", "application/json", bytes.NewBufferString(`{"username":"newowner","password":"owner123"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer loginResponse.Body.Close()
	var login struct {
		Code int `json:"code"`
		Data struct {
			Token string `json:"token"`
			User  User   `json:"user"`
		} `json:"data"`
	}
	if err := json.NewDecoder(loginResponse.Body).Decode(&login); err != nil {
		t.Fatal(err)
	}
	if loginResponse.StatusCode != http.StatusOK || login.Code != 200 || login.Data.Token == "" || login.Data.User.Role != RoleUser {
		t.Fatalf("login response=%+v status=%d", login, loginResponse.StatusCode)
	}
}

func TestHTTPRejectsTrailingJSONAndReturnsRequestID(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	request := httptest.NewRequest(http.MethodPost, "/api/user/login", bytes.NewBufferString(`{"username":"testuser","password":"user123"}{}`))
	request.Header.Set("X-Request-ID", "request-from-test")
	response := httptest.NewRecorder()
	NewHandler(service).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("X-Request-ID") != "request-from-test" {
		t.Fatalf("request id header = %q", response.Header().Get("X-Request-ID"))
	}
	var body struct {
		Code      int    `json:"code"`
		RequestID string `json:"requestId"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Code != 400 || body.RequestID != "request-from-test" {
		t.Fatalf("body=%+v", body)
	}
}

func TestHTTPRejectsMalformedResourceID(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	token, _, _, err := service.Login(context.Background(), "testuser", "user123")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/pet/not-a-number", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	NewHandler(service).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}
