package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	_ "github.com/YnovFinalProject/ForumGO/internal/data"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

var googleOauthConfig = &oauth2.Config{
	RedirectURL:  "https://app1.traefik.me/auth/google/callback",
	ClientID:     "#######################.apps.googleusercontent.com", //put your ID
	ClientSecret: "#######################",
	Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
	Endpoint:     google.Endpoint,
}

const oauthGoogleUrlAPI = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="

func OauthGoogleLogin(w http.ResponseWriter, r *http.Request) {

	// Create oauthState cookie
	oauthState := generateStateOauthCookie(w)

	u := googleOauthConfig.AuthCodeURL(oauthState)
	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

type UserInfo struct {
	IDGoogle      string `json:"id"`
	IDGithub      string `json:"node_id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Picture       string `json:"picture"`
	AvatarUrl     string `json:"avatar_url"`
}

func OauthGoogleCallback(w http.ResponseWriter, r *http.Request) {
	oauthState, _ := r.Cookie("oauthstate")

	if r.FormValue("state") != oauthState.Value {
		fmt.Println("invalid oauth google state")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	datas, err := getUserDataFromGoogle(r.FormValue("code"))
	if err != nil {
		fmt.Println(err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	var userInfo UserInfo
	err = json.Unmarshal([]byte(datas), &userInfo)
	if err != nil {
		fmt.Println("Erreur lors du décodage JSON :", err)
		return
	}

	http.Redirect(w, r, "/register_action?mailGoogle="+userInfo.Email+"&img="+userInfo.Picture, http.StatusTemporaryRedirect)
}

func generateStateOauthCookie(w http.ResponseWriter) string {
	var expiration = time.Now().Add(20 * time.Minute)

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "oauthstate", Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)

	return state
}

func getUserDataFromGoogle(code string) ([]byte, error) {
	// Use code to get token and get user info from Google.

	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}
	response, err := http.Get(oauthGoogleUrlAPI + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed read response: %s", err.Error())
	}
	return contents, nil
}

///// GITHUB

func LoggedinHandler(w http.ResponseWriter, r *http.Request, githubData string) {
	if githubData == "" {
		// Unauthorized users get an unauthorized message
		fmt.Fprintf(w, "UNAUTHORIZED!")
		return
	}

	// Set return type JSON
	w.Header().Set("Content-type", "application/json")

	var userInfo UserInfo
	err := json.Unmarshal([]byte(githubData), &userInfo)
	if err != nil {
		fmt.Println("Erreur lors du décodage JSON :", err)
		return
	}
	http.Redirect(w, r, "/register_action?IDGithub="+userInfo.IDGithub+"&img="+userInfo.AvatarUrl, http.StatusTemporaryRedirect)

}

func getGithubClientID() string {

	githubClientID := "############""

	return githubClientID
}

func getGithubClientSecret() string {

	githubClientSecret := "#########################"

	return githubClientSecret
}

func GithubLoginHandler(w http.ResponseWriter, r *http.Request) {
	// Get the environment variable
	githubClientID := getGithubClientID()

	// Create the dynamic redirect URL for login
	redirectURL := fmt.Sprintf(
		"https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s",
		githubClientID,
		"https://app1.traefik.me/login/github/callback",
	)

	http.Redirect(w, r, redirectURL, 301)
}

func GithubCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	githubAccessToken := getGithubAccessToken(code)

	githubData := getGithubData(githubAccessToken)

	LoggedinHandler(w, r, githubData)
}

func getGithubAccessToken(code string) string {

	clientID := getGithubClientID()
	clientSecret := getGithubClientSecret()

	// Set us the request body as JSON
	requestBodyMap := map[string]string{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"code":          code,
	}
	requestJSON, _ := json.Marshal(requestBodyMap)

	// POST request to set URL
	req, reqerr := http.NewRequest(
		"POST",
		"https://github.com/login/oauth/access_token",
		bytes.NewBuffer(requestJSON),
	)
	if reqerr != nil {
		log.Panic("Request creation failed")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Get the response
	resp, resperr := http.DefaultClient.Do(req)
	if resperr != nil {
		log.Panic("Request failed")
	}

	// Response body converted to stringified JSON
	respbody, _ := ioutil.ReadAll(resp.Body)

	// Represents the response received from Github
	type githubAccessTokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}

	// Convert stringified JSON to a struct object of type githubAccessTokenResponse
	var ghresp githubAccessTokenResponse
	json.Unmarshal(respbody, &ghresp)

	// Return the access token (as the rest of the
	// details are relatively unnecessary for us)
	return ghresp.AccessToken
}

func getGithubData(accessToken string) string {
	// Get request to a set URL
	req, reqerr := http.NewRequest(
		"GET",
		"https://api.github.com/user",
		nil,
	)
	if reqerr != nil {
		log.Panic("API Request creation failed")
	}

	// Set the Authorization header before sending the request
	// Authorization: token XXXXXXXXXXXXXXXXXXXXXXXXXXX
	authorizationHeaderValue := fmt.Sprintf("token %s", accessToken)
	req.Header.Set("Authorization", authorizationHeaderValue)

	// Make the request
	resp, resperr := http.DefaultClient.Do(req)
	if resperr != nil {
		log.Panic("Request failed")
	}

	// Read the response as a byte slice
	respbody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(respbody)) // Convert byte slice to string and return
	return string(respbody)
}
