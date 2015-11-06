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
)

func (cli *Spartan) CreateRole(role string, ug string, roleHandle string, roleType string, description string) (*string, error) {
	var buf bytes.Buffer
	url := cli.baseUrl + "/role/create"
	data := map[string]string{"name": role, "usergroup": ug, "rolehandle": roleHandle, "roletype": roleType, "description": description}

	_, code, err := DialHttp(url, "POST", data, cli.userJwt, "", cli.insecureSkipVerify)
	if err != nil {
		return nil, err
	}

	if code == http.StatusCreated {
		buf.WriteString("role " + role + " created successfully")
		err = nil
	} else {
		buf.WriteString("failed to create role " + role)
		err = fmt.Errorf("failed to create role %v", role)
	}
	s := buf.String()
	return &s, err
}

func (cli *Spartan) ShowRole(role string) (*string, error) {
	var buf bytes.Buffer
	url := cli.baseUrl + "/role/" + role

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
		buf.WriteString("failed to get role " + role)
		err = fmt.Errorf("failed to get role %v", role)
	}
	s := buf.String()

	return &s, nil
}

func (cli *Spartan) ListRoles() (*string, error) {
	var buf bytes.Buffer
	url := cli.baseUrl + "/role/all/"

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
		buf.WriteString("failed to get all roles")
		err = fmt.Errorf("failed to get all roles")
	}
	s := buf.String()

	return &s, nil
}

func (cli *Spartan) AddMemberToRole(role string, app string) (*string, error) {
	var buf bytes.Buffer
	url := cli.baseUrl + "/role/addmember"
	data := map[string]string{"role": role, "appname": app}

	_, code, err := DialHttp(url, "POST", data, cli.userJwt, "", cli.insecureSkipVerify)
	if err != nil {
		return nil, err
	}

	if code == http.StatusOK {
		buf.WriteString("app " + app + " added to role " + role + " successfully")
		err = nil
	} else {
		buf.WriteString("failed to add to role " + role)
		err = fmt.Errorf("failed to add to role %v", role)
	}
	s := buf.String()
	return &s, err
}

func (cli *Spartan) RemoveMemberFromRole(role string, app string) (*string, error) {
	var buf bytes.Buffer
	url := cli.baseUrl + "/role/removemember"
	data := map[string]string{"role": role, "appname": app}

	_, code, err := DialHttp(url, "POST", data, cli.userJwt, "", cli.insecureSkipVerify)
	if err != nil {
		return nil, err
	}

	if code == http.StatusOK {
		buf.WriteString("app " + app + " removed successfully")
		err = nil
	} else {
		buf.WriteString("failed to remove app " + app)
		err = fmt.Errorf("failed to remove app %v", app)
	}
	s := buf.String()
	return &s, err
}

func (cli *Spartan) RemoveRole(role string) (*string, error) {
	var buf bytes.Buffer
	url := cli.baseUrl + "/role/delete"
	data := map[string]string{"name": role}

	_, code, err := DialHttp(url, "POST", data, cli.userJwt, "", cli.insecureSkipVerify)
	if err != nil {
		return nil, err
	}

	if code == http.StatusOK {
		buf.WriteString("Removed role " + role + " successfully")
		err = nil
	} else {
		buf.WriteString("failed to remove role " + role)
		err = fmt.Errorf("failed to remove app %v", role)
	}
	s := buf.String()
	return &s, err
}
