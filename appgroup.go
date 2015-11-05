//
// Copyright 2015, Yahoo Inc.
// Copyrights licensed under the New BSD License. See the
// accompanying LICENSE.txt file for terms.
//
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
)

func (cli *Spartan) CreateApp(app string, ug string, description string) (*string, error) {
	var buf bytes.Buffer
	url := cli.baseUrl + "/app/create"
	data := map[string]string{"name": app, "usergroup": ug, "description": description}

	_, code, err := DialHttp(url, "POST", data, cli.userJwt, "", cli.insecureSkipVerify)
	if err != nil {
		return nil, err
	}

	if code == http.StatusCreated {
		buf.WriteString("app " + app + " created successfully")
		err = nil
	} else {
		buf.WriteString("failed to create app " + app)
		err = fmt.Errorf("failed to create app %v", app)
	}
	s := buf.String()
	return &s, err
}

func (cli *Spartan) ShowApp(app string) (*string, error) {
	var buf bytes.Buffer
	url := cli.baseUrl + "/app/" + app

	body, code, err := DialHttp(url, "GET", nil, cli.userJwt, "", cli.insecureSkipVerify)
	if err != nil {
		return nil, err
	}
	if code == http.StatusOK {
		//res := UgResponse{}
		//json.Unmarshal(body, &res)
		buf.WriteString(string(body))
		err = nil
	} else {
		buf.WriteString("failed to get app " + app)
		err = fmt.Errorf("failed to get app %v", app)
	}
	s := buf.String()

	return &s, nil
}

func (cli *Spartan) ListApps() (*string, error) {
	var buf bytes.Buffer
	url := cli.baseUrl + "/app/all/"

	body, code, err := DialHttp(url, "GET", nil, cli.userJwt, "", cli.insecureSkipVerify)
	if err != nil {
		return nil, err
	}
	if code == http.StatusOK {
		//res := UgResponse{}
		//json.Unmarshal(body, &res)
		buf.WriteString(string(body))
		err = nil
	} else {
		buf.WriteString("failed to get all apps")
		err = fmt.Errorf("failed to get all apps")
	}
	s := buf.String()

	return &s, nil
}

func (cli *Spartan) AddMemberToApp(app string, identityFile string, identityType string, role string) (*string, error) {
	var buf bytes.Buffer
	url := cli.baseUrl + "/app/addmember"

	pubKey, err := ioutil.ReadFile(identityFile)
	if err != nil {
		return nil, err
	}
	shaBytes := sha256.Sum256(pubKey)
	identitySha := hex.EncodeToString(shaBytes[:])

	data := map[string]string{"app": app, "identity": identitySha, "type": identityType, "role": role}
	_, code, err := DialHttp(url, "POST", data, cli.userJwt, "", cli.insecureSkipVerify)
	if err != nil {
		return nil, err
	}

	if code == http.StatusOK {
		buf.WriteString("identity " + identitySha + " added to app " + app + " successfully")
		err = nil
	} else {
		buf.WriteString("failed to add to app " + app)
		err = fmt.Errorf("failed to add to app %v", app)
	}
	s := buf.String()
	return &s, err
}

func (cli *Spartan) RemoveMemberFromApp(identity string) (*string, error) {
	var buf bytes.Buffer
	url := cli.baseUrl + "/app/removemember"
	data := map[string]string{"identity": identity}

	_, code, err := DialHttp(url, "POST", data, cli.userJwt, "", cli.insecureSkipVerify)
	if err != nil {
		return nil, err
	}

	if code == http.StatusOK {
		buf.WriteString("identity " + identity + " removed successfully")
		err = nil
	} else {
		buf.WriteString("failed to remove identity " + identity)
		err = fmt.Errorf("failed to remove identity %v", identity)
	}
	s := buf.String()
	return &s, err
}

func (cli *Spartan) RemoveApp(app string) (*string, error) {
	var buf bytes.Buffer
	url := cli.baseUrl + "/app/delete"
	data := map[string]string{"name": app}

	_, code, err := DialHttp(url, "POST", data, cli.userJwt, "", cli.insecureSkipVerify)
	if err != nil {
		return nil, err
	}

	if code == http.StatusOK {
		buf.WriteString("Removed app " + app + " successfully")
		err = nil
	} else {
		buf.WriteString("failed to remove app " + app)
		err = fmt.Errorf("failed to remove app %v", app)
	}
	s := buf.String()
	return &s, err
}
