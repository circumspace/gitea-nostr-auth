package handler

import (
	"encoding/json"
	"net/http"
)

type OIDCConfiguration struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserInfoEndpoint                 string   `json:"userinfo_endpoint"`
	JwksURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
}

func (h *Handler) OIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	baseURL := h.cfg.Server.BaseURL

	config := OIDCConfiguration{
		Issuer:                           baseURL,
		AuthorizationEndpoint:            baseURL + "/authorize",
		TokenEndpoint:                    baseURL + "/token",
		UserInfoEndpoint:                 baseURL + "/userinfo",
		JwksURI:                          baseURL + "/.well-known/jwks.json",
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		ClaimsSupported: []string{
			"sub",
			"iss",
			"aud",
			"exp",
			"iat",
			"name",
			"preferred_username",
			"email",
		},
		GrantTypesSupported: []string{"authorization_code"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	// For simplicity, we'll use a static JWKS
	// In production, this should be dynamically generated from actual keys
	jwks := JWKSet{
		Keys: []JWK{},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}
