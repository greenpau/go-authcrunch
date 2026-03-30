// Copyright 2022 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authproxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/pkg/system"
	"github.com/greenpau/go-authcrunch/pkg/util"
	"go.uber.org/zap"
)

// RemoteAuthenticator holds connection to remote identity store.
type RemoteAuthenticator struct {
	realmName string
	cryptoKey *kms.CryptoKey
	config    *RealmAuthProxyConfig
	encryptor *system.Encryptor
	logger    *zap.Logger
}

// NewRemoteAuthenticator returns an instance of RemoteAuthenticator.
func NewRemoteAuthenticator(realmName string, cryptoKey *kms.CryptoKey, config *RealmAuthProxyConfig, logger *zap.Logger) (*RemoteAuthenticator, error) {
	r := &RemoteAuthenticator{
		realmName: realmName,
		cryptoKey: cryptoKey,
		config:    config,
		logger:    logger,
	}

	if cryptoKey == nil {
		return nil, fmt.Errorf("crypto key is nil")
	}

	cryptoKeyInfo := cryptoKey.GetKeyInfo()

	secretKey, err := system.ParseKeyFromString(cryptoKey.Config.Secret)
	if err != nil {
		return nil, fmt.Errorf("crypto key is nil")
	}

	enc, err := system.NewEncryptor(cryptoKeyInfo.ID, secretKey)
	if err != nil {
		return nil, fmt.Errorf("crypto key is nil")
	}
	r.encryptor = enc

	return r, nil
}

// GetName returns the realm name associated with the RemoteAuthenticator.
func (r *RemoteAuthenticator) GetName() string {
	return r.realmName
}

// BasicAuth performs basic authentication with the RemoteAuthenticator.
func (r *RemoteAuthenticator) BasicAuth(apr *Request) error {
	messageData := &system.BasicAuthRequestMessage{
		Kind:    system.BasicAuthRequestKindKeyword,
		Realm:   r.realmName,
		Address: apr.Address,
	}

	decodedSecret, err := base64.StdEncoding.DecodeString(apr.Secret)
	if err != nil {
		return err
	}
	creds := strings.SplitN(string(decodedSecret), ":", 2)
	messageData.Username = creds[0]
	messageData.Password = creds[1]

	reqMsg, err := system.ParseMessage(messageData)
	if err != nil {
		return err
	}

	if err := reqMsg.Validate(); err != nil {
		return fmt.Errorf("failed to validate basic auth message: %v", err)
	}

	reqData, err := r.encryptor.EncryptMessage(reqMsg)
	if err != nil {
		return err
	}

	respMsgRaw, err := r.doRequest(reqData)
	if err != nil {
		return err
	}

	switch respMsg := respMsgRaw.(type) {
	case *system.AuthResponseMessage:
		if respMsg.Authenticated {
			payload, err := json.Marshal(respMsg.UserData)
			if err != nil {
				return fmt.Errorf("failed serializing user data: %v", err)
			}
			apr.Response.Payload = string(payload)
			apr.Response.IsPlainPayload = true
			return nil
		}
	default:
		return fmt.Errorf("received unsupported message type in response to basic auth request: %T", respMsg)
	}

	return fmt.Errorf("not authenticated")
}

// APIKeyAuth performs API key authentication with the RemoteAuthenticator.
func (r *RemoteAuthenticator) APIKeyAuth(apr *Request) error {
	messageData := &system.APIKeyAuthRequestMessage{
		Kind:    system.APIKeyAuthRequestKindKeyword,
		APIKey:  apr.Secret,
		Realm:   r.realmName,
		Address: apr.Address,
	}

	reqMsg, err := system.ParseMessage(messageData)
	if err != nil {
		return err
	}

	if err := reqMsg.Validate(); err != nil {
		return fmt.Errorf("failed to validate api key auth message: %v", err)
	}

	reqData, err := r.encryptor.EncryptMessage(reqMsg)
	if err != nil {
		return err
	}

	respMsgRaw, err := r.doRequest(reqData)
	if err != nil {
		return err
	}

	switch respMsg := respMsgRaw.(type) {
	case *system.AuthResponseMessage:
		if respMsg.Authenticated {
			payload, err := json.Marshal(respMsg.UserData)
			if err != nil {
				return fmt.Errorf("failed serializing user data: %v", err)
			}
			apr.Response.Payload = string(payload)
			apr.Response.IsPlainPayload = true
			return nil
		}
	default:
		return fmt.Errorf("received unsupported message type in response to api key auth request: %T", respMsg)
	}

	return fmt.Errorf("not authenticated")
}

func (r *RemoteAuthenticator) buildRemoteURL() string {
	url := r.config.RemoteAddr
	if !strings.HasSuffix(r.config.RemoteAddr, "/") {
		url += "/"
	}
	url += "api/system"
	return url
}

func (r *RemoteAuthenticator) doRequest(reqData string) (system.Message, error) {
	url := r.buildRemoteURL()
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewBuffer([]byte(reqData)))
	req.Header.Set("Content-Type", "text/plain; charset=UTF-8")
	browser, err := util.NewBrowser()
	if err != nil {
		return nil, err
	}
	browser.SetTimeout(2 * time.Second)
	respBody, resp, err := browser.Do(req)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("response is nil")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with response %d", resp.StatusCode)
	}

	if !strings.HasPrefix(respBody, "v4.local.") {
		return nil, fmt.Errorf("unexpected system message response: %s", respBody)
	}

	respMsg, err := r.encryptor.DecryptMessage(respBody)
	if err != nil {
		return nil, err
	}

	return respMsg, err
}
