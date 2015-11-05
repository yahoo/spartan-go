//
// Copyright 2015, Yahoo Inc.
// Copyrights licensed under the New BSD License. See the
// accompanying LICENSE.txt file for terms.
//
package main

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
)

func (cli *Spartan) CreateUserGroup(ug string, description string) (*string, error) {
	var buf bytes.Buffer
	url := cli.baseUrl + "/usergroup/create"
	data := map[string]string{"name": ug, "description": description}

	body, code, err := DialHttp(url, "POST", data, cli.userJwt, "", cli.insecureSkipVerify)
	if err != nil {
		return nil, err
	}

	if code == http.StatusCreated {
		buf.WriteString("usergroup " + ug + " created successfully")
		err = nil
	} else {
		bodyStr, _ := strconv.Unquote(string(body))
		buf.WriteString("failed to create usergroup " + ug + ", message: " + bodyStr)
		err = fmt.Errorf("failed to create usergroup %v, message: %v", ug, bodyStr)
	}
	s := buf.String()
	return &s, err
}

func (cli *Spartan) ShowUserGroup(ug string) (*string, error) {
	var buf bytes.Buffer
	url := cli.baseUrl + "/usergroup/" + ug

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
		bodyStr, _ := strconv.Unquote(string(body))
		buf.WriteString("failed to get usergroup " + ug + ", message: " + bodyStr)
		err = fmt.Errorf("failed to get usergroup %v, message: %v", ug, bodyStr)
	}
	s := buf.String()

	return &s, nil
}

func (cli *Spartan) ListUserGroups() (*string, error) {
	var buf bytes.Buffer
	url := cli.baseUrl + "/usergroup/all/"

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
		bodyStr, _ := strconv.Unquote(string(body))
		buf.WriteString("failed to get all usergroups " + ", message: " + bodyStr)
		err = fmt.Errorf("failed to get all usergroups, message: %v", bodyStr)
	}
	s := buf.String()

	return &s, nil
}

func (cli *Spartan) AddToUserGroup(ug string, userid string, usertype string, role string) (*string, error) {
	var buf bytes.Buffer
	url := cli.baseUrl + "/usergroup/adduser"
	data := map[string]string{"group": ug, "userid": userid, "type": usertype, "role": role}

	_, code, err := DialHttp(url, "POST", data, cli.userJwt, "", cli.insecureSkipVerify)
	if err != nil {
		return nil, err
	}

	if code == http.StatusOK {
		buf.WriteString("userid " + userid + " added to usergroup " + ug + " successfully")
		err = nil
	} else {
		buf.WriteString("failed to add to usergroup " + ug)
		err = fmt.Errorf("failed to add to usergroup %v", ug)
	}
	s := buf.String()
	return &s, err
}

func (cli *Spartan) RemoveFromUserGroup(ug string, userid string) (*string, error) {
	var buf bytes.Buffer
	url := cli.baseUrl + "/usergroup/removeuser"
	data := map[string]string{"group": ug, "userid": userid}

	_, code, err := DialHttp(url, "POST", data, cli.userJwt, "", cli.insecureSkipVerify)
	if err != nil {
		return nil, err
	}

	if code == http.StatusOK {
		buf.WriteString("userid " + userid + " removed from usergroup " + ug + " successfully")
		err = nil
	} else {
		buf.WriteString("failed to remove from usergroup " + ug)
		err = fmt.Errorf("failed to remove from usergroup %v", ug)
	}
	s := buf.String()
	return &s, err
}

func (cli *Spartan) RemoveUserGroup(ug string) (*string, error) {
	var buf bytes.Buffer
	url := cli.baseUrl + "/usergroup/delete"
	data := map[string]string{"group": ug}

	_, code, err := DialHttp(url, "POST", data, cli.userJwt, "", cli.insecureSkipVerify)
	if err != nil {
		return nil, err
	}

	if code == http.StatusOK {
		buf.WriteString("Removed usergroup " + ug + " successfully")
		err = nil
	} else {
		buf.WriteString("failed to remove usergroup " + ug)
		err = fmt.Errorf("failed to remove usergroup %v", ug)
	}
	s := buf.String()
	return &s, err
}
