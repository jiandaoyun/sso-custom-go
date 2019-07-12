package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	acs      = "http://localhost:443/sso/custom/5d03911587833c7bf2e19c38/acs"
	issuer   = "com.example"
	username = "06270a5411f"
	secret   = "6xv9gMV299OVBfxTVgUSyW2v"
)

func ValidBody(body jwt.MapClaims) bool {
	return body["iss"] == "com.jiandaoyun" && body["aud"] == issuer && body["type"] == "sso_req"
}

func ValidToken(query string) bool {
	token, err := jwt.Parse(query, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected Signing Method: %v ", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return false
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	return ok && token.Valid && ValidBody(claims)
}

func GetTokenByUsername(username string) (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"type":     "sso_res",
		"username": username,
		"iss":      issuer,
		"aud":      "com.jiandaoyun",
		"nbf":      now.Unix(),
		"iat":      now.Unix(),
		"exp":      now.Add(1 * time.Minute).Unix(),
	})
	return token.SignedString([]byte(secret))
}

func BuildResponseUri(token string, state string) string {
	target := acs + "?response=" + token
	if state != "" {
		target += "&state=" + state
	}
	return target
}

func handler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	reqToken := query.Get("request")
	if ok := ValidToken(reqToken); ok {
		if resToken, err := GetTokenByUsername(username); err == nil {
			target := BuildResponseUri(resToken, query.Get("state"))
			http.Redirect(w, r, target, http.StatusSeeOther)
		}
		w.WriteHeader(404)
	}
	w.WriteHeader(404)
}

func main() {
	http.HandleFunc("/sso", handler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
