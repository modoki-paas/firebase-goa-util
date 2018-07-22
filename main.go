package firebasegoa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/auth0/go-jwt-middleware"
	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	"github.com/goadesign/goa/middleware/security/jwt"
)

const (
	jwksEndpoint = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
)

// GetPemCert retrieves public keys to verify tokens
type GetPemCert func(*jwtgo.Token) (string, error)

// BridgeMiddlewareHandler converts jwt middleware into goa middleware.
type BridgeMiddlewareHandler struct {
	Middleware *jwtmiddleware.JWTMiddleware
}

// Handle implements goa.Middleware interface
func (h *BridgeMiddlewareHandler) Handle(nextHandler goa.Handler) goa.Handler {
	return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
		if err := h.Middleware.CheckJWT(rw, req); err != nil {
			return jwt.ErrJWTError(err)
		}

		token := req.Context().Value(h.Middleware.Options.UserProperty).(*jwtgo.Token)
		req = req.WithContext(jwt.WithJWT(req.Context(), token))

		return nextHandler(ctx, rw, req)
	}
}

// NewJWTMiddleware returns a jwt middleware for Auth0
func NewJWTMiddleware(aud, iss string, getPemCert GetPemCert) *jwtmiddleware.JWTMiddleware {
	return jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwtgo.Token) (interface{}, error) {
			// Verify 'aud' claim
			checkAud := token.Claims.(jwtgo.MapClaims).VerifyAudience(aud, false)
			if !checkAud {
				return token, errors.New("Invalid audience")
			}
			// Verify 'iss' claim
			checkIss := token.Claims.(jwtgo.MapClaims).VerifyIssuer(iss, false)
			if !checkIss {
				return token, errors.New("Invalid issuer")
			}

			cert, err := getPemCert(token)
			if err != nil {
				panic(err.Error())
			}

			result, _ := jwtgo.ParseRSAPublicKeyFromPEM([]byte(cert))
			return result, nil
		},
		SigningMethod: jwtgo.SigningMethodRS256,
	})
}

// NewGetPemCert creates a cacheable pem getter function
func NewGetPemCert() GetPemCert {
	var group singleflight.Group
	var updatedTime time.Time
	var cacheJWKS *Jwks

	return func(token *jwtgo.Token) (string, error) {
		v, err, _ := group.Do("jwks", func() (interface{}, error) {
			if cacheJWKS != nil && time.Now().Sub(updatedTime) < 30*time.Minute {
				return cacheJWKS, nil
			}

			resp, err := http.Get(jwksEndpoint)

			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()

			var jwks Jwks
			err = json.NewDecoder(resp.Body).Decode(&jwks)

			if err != nil {
				return nil, err
			}

			cacheJWKS = &jwks
			updatedTime = time.Now()

			return &jwks, nil
		})

		if err != nil {
			return "", err
		}

		jwks := v.(*Jwks) // Do not edit
		var cert string

		cert, ok := (*jwks)[fmt.Sprint(token.Header["kid"])]

		if !ok {
			err := errors.New("Unable to find appropriate key")
			return "", err
		}

		return cert, nil
	}
}
