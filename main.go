//
// Copyright 2015, Yahoo Inc.
// Copyrights licensed under the New BSD License. See the
// accompanying LICENSE.txt file for terms.
//
package main

import (
	"bytes"
	"code.google.com/p/gopass"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

type Spartan struct {
	baseUrl            string
	userid             string
	userJwt            string
	caPath             string
	insecureSkipVerify bool
	verbose            bool
}

type JwtResponse struct {
	Token string `json:"token"`
}

//type UgResponse struct {
//	Token string `json:"token"`
//}

func defaultBaseUrl() string {
	s := os.Getenv("SPARTAN_URL")
	if s != "" {
		return s
	}
	return "http://localhost:3000/v1"
}

func defaultUser() string {
	s := os.Getenv("SPARTAN_USER")
	if s != "" {
		return s
	}
	return "admin@example.com"
}

func getHomeDir() string {
	s := os.Getenv("HOME")
	if s != "" {
		return s + "/"
	}

	s, _ = os.Getwd()
	return s + "/"
}

func (cli *Spartan) process(params []string) (*string, error) {
	argc := len(params)
	if argc >= 1 {
		cmd := params[0]
		//args := params[1:]
		switch cmd {
		case "create-usergroup":
			if argc >= 2 {
				return cli.CreateUserGroup(params[1], strings.Join(params[2:], " "))
			} else {
				return nil, fmt.Errorf("Invalid number of arguments")
			}
		case "show-usergroup":
			if argc >= 2 {
				return cli.ShowUserGroup(params[1])
			} else {
				return nil, fmt.Errorf("Invalid number of arguments")
			}
		case "list-usergroups":
			return cli.ListUserGroups()
		case "add-to-usergroup":
			if argc >= 3 {
				var usertype, role string
				if argc >= 5 {
					role = params[4]
				}
				if argc >= 4 {
					usertype = params[3]
				}
				return cli.AddToUserGroup(params[1], params[2], usertype, role)
			} else {
				return nil, fmt.Errorf("Invalid number of arguments")
			}
		case "remove-from-usergroup":
			if argc >= 3 {
				return cli.RemoveFromUserGroup(params[1], params[2])
			} else {
				return nil, fmt.Errorf("Invalid number of arguments")
			}
		case "remove-usergroup":
			if argc >= 2 {
				return cli.RemoveUserGroup(params[1])
			} else {
				return nil, fmt.Errorf("Invalid number of arguments")
			}
		case "create-app":
			if argc >= 3 {
				return cli.CreateApp(params[1], params[2], strings.Join(params[3:], " "))
			} else {
				return nil, fmt.Errorf("Invalid number of arguments")
			}
		case "show-app":
			if argc >= 2 {
				return cli.ShowApp(params[1])
			} else {
				return nil, fmt.Errorf("Invalid number of arguments")
			}
		case "list-apps":
			return cli.ListApps()
		case "add-to-app":
			if argc >= 3 {
				var identityType, role string
				if argc >= 5 {
					role = params[4]
				}
				if argc >= 4 {
					identityType = params[3]
				}
				return cli.AddMemberToApp(params[1], params[2], identityType, role)
			} else {
				return nil, fmt.Errorf("Invalid number of arguments")
			}
		case "remove-from-app":
			if argc >= 2 {
				return cli.RemoveMemberFromApp(params[1])
			} else {
				return nil, fmt.Errorf("Invalid number of arguments")
			}
		case "remove-app":
			if argc >= 2 {
				return cli.RemoveApp(params[1])
			} else {
				return nil, fmt.Errorf("Invalid number of arguments")
			}
		case "create-role":
			if argc >= 3 {
				var roleHandle, roleType string
				if argc >= 5 {
					roleType = params[4]
				}
				if argc >= 4 {
					roleHandle = params[3]
				}
				return cli.CreateRole(params[1], params[2], roleHandle, roleType, strings.Join(params[5:], " "))
			} else {
				return nil, fmt.Errorf("Invalid number of arguments")
			}
		case "show-role":
			if argc >= 2 {
				return cli.ShowRole(params[1])
			} else {
				return nil, fmt.Errorf("Invalid number of arguments")
			}
		case "list-roles":
			return cli.ListRoles()
		case "add-to-role":
			if argc >= 3 {
				return cli.AddMemberToRole(params[1], params[2])
			} else {
				return nil, fmt.Errorf("Invalid number of arguments")
			}
		case "remove-from-role":
			if argc >= 3 {
				return cli.RemoveMemberFromRole(params[1], params[2])
			} else {
				return nil, fmt.Errorf("Invalid number of arguments")
			}
		case "remove-role":
			if argc >= 2 {
				return cli.RemoveRole(params[1])
			} else {
				return nil, fmt.Errorf("Invalid number of arguments")
			}

		default:
			return nil, fmt.Errorf("unrecognized command %v", cmd)
		}
	}
	return nil, fmt.Errorf("Invalid arguments")
}

func getCachedToken() string {
	tokenFilePath := getHomeDir() + ".spartan_token"
	data, err := ioutil.ReadFile(tokenFilePath)
	token := ""
	if err != nil {
		fmt.Println("unable to read from file " + tokenFilePath)
		return ""
	}
	// check if the token is valid
	_, err = jwt.Parse(string(data), func(token *jwt.Token) (interface{}, error) {
		return "foobar", nil
	})

	if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			fmt.Println("Invalid token string")
			_ = os.Remove(tokenFilePath)
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			// Token is either expired or not active yet
			fmt.Println("token expired")
			_ = os.Remove(tokenFilePath)
		} else if ve.Errors&(jwt.ValidationErrorSignatureInvalid) != 0 {
			// TODO: race condition here, if token is very close to expiry
			fmt.Println("Token not expired, good to use")
			token = string(data)
		} else {
			fmt.Println("Couldn't handle this token:", err)
			_ = os.Remove(tokenFilePath)
		}
	}
	return token
}

func cacheToken(token string) {
	tokenFilePath := getHomeDir() + ".spartan_token"
	fmt.Println("caching token at " + tokenFilePath)
	_ = ioutil.WriteFile(tokenFilePath, []byte(token), 0644)
}

func DialHttp(url string, method string, data map[string]string, token string, caPath string, insecureSkipVerify bool) ([]byte, int, error) {

	var req *http.Request
	var err error
	var body []byte
	certs := x509.NewCertPool()
	if caPath != "" {
		// custom CA specified
		pemData, err := ioutil.ReadFile(caPath)
		if err != nil {
			return nil, 0, err
		}
		certs.AppendCertsFromPEM(pemData)
	}
	if data != nil {
		dataM, _ := json.Marshal(data)
		fmt.Println("request data::" + string(dataM))
		req, err = http.NewRequest(method, url, bytes.NewBuffer(dataM))
	} else {
		req, err = http.NewRequest(method, url, nil)
	}

	if err != nil {
		err = fmt.Errorf("Unable to create http request")
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("x-spartan-auth-token", token)
	}

	//client := &http.Client{}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: certs, InsecureSkipVerify: insecureSkipVerify},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
		err = fmt.Errorf("Failed to connect to server")
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		body, _ = ioutil.ReadAll(resp.Body)
	}
	return body, resp.StatusCode, nil
}

func getUserJwt(userid string, baseUrl string, insecureSkipVerify bool) (*string, error) {

	if cachedToken := getCachedToken(); cachedToken != "" {
		return &cachedToken, nil
	}

	fmt.Fprintf(os.Stderr, "Enter password for "+userid+": ")
	pass, err := gopass.GetPass("")
	if err != nil {
		fmt.Println("*** No password provided ***")
		os.Exit(1)
	}
	url := baseUrl + "/auth/token"
	data := map[string]string{"userid": userid, "passwd": pass}
	body, code, err := DialHttp(url, "POST", data, "", "", insecureSkipVerify)
	if err != nil {
		return nil, err
	}
	if code == http.StatusOK {
		res := JwtResponse{}
		json.Unmarshal(body, &res)
		fmt.Println("Using token: " + res.Token)
		cacheToken(res.Token)
		return &res.Token, nil
	} else {
		err = fmt.Errorf("Invalid credentials")
		return nil, err
	}
}

func usage(help bool) string {
	var b bytes.Buffer
	//non interactive help
	b.WriteString("NAME\n")
	b.WriteString("    spartan - commandline utility to interact with spartan\n\n")
	b.WriteString("SYNOPSIS\n")
	b.WriteString("    spartan [flags] command [params]\n\n")
	b.WriteString("OPTIONS\n")
	b.WriteString("   -u <userid>              userid to be used\n")
	b.WriteString("   -s <url>                 base spartan URL to be used\n")
	b.WriteString("   -c <cert bundle path>    CA crt bundle path, if not default\n")
	b.WriteString("   -v                       verbose\n")
	b.WriteString("\n\n")
	if help {
		b.WriteString("STANDARD COMMANDS\n\n")
		b.WriteString(" Usergroup commands\n")
		b.WriteString("\n")
		b.WriteString("     show-usergroup <usergroup>\n")
		b.WriteString("     create-usergroup <usergroup> [description ...]\n")
		b.WriteString("     remove-usergroup <usergroup>\n")
		b.WriteString("     add-to-usergroup <usergroup> <userid> [<usertype> <role>]\n")
		b.WriteString("     remove-from-usergroup <usergroup> <usergroup>\n")
		b.WriteString("     list-usergroups\n")
		b.WriteString("\n")
		b.WriteString(" App group commands\n")
		b.WriteString("\n")
		b.WriteString("     show-app <app>\n")
		b.WriteString("     create-app <app> <usergroup> [description ...]\n")
		b.WriteString("     remove-app <app>\n")
		b.WriteString("     add-to-app <app> <identity file path> [<identityType> <role>]\n")
		b.WriteString("     remove-from-app <identity>\n")
		b.WriteString("     list-apps\n")
		b.WriteString("\n")
		b.WriteString(" Role commands\n")
		b.WriteString("\n")
		b.WriteString("     show-role <role>\n")
		b.WriteString("     create-role <role> <usergroup> [<roleHandle> <roleType> [description ...]]\n")
		b.WriteString("     remove-role <role>\n")
		b.WriteString("     add-to-role <role> <app>\n")
		b.WriteString("     remove-from-role <role> <app>\n")
		b.WriteString("     list-roles\n")
		b.WriteString("\n")

	}
	b.WriteString("type 'spartan help' to see all available commands\n")
	b.WriteString("type 'spartan help [command]' for usage of the specified command")
	return b.String()

}

func main() {
	baseUrl := flag.String("s", defaultBaseUrl(), "Base spartan URL to be used")
	userid := flag.String("u", defaultUser(), "userid to be used")
	caPath := flag.String("c", "", "CA cert bundle to be used")
	verbose := flag.Bool("v", false, "verbose mode")
	insecureSkipVerify := flag.Bool("k", false, "skip verification of cert hostname and chain")

	flag.Usage = func() {
		fmt.Println(usage(false))
	}

	flag.Parse()

	args := flag.Args()

	if len(args) == 0 {
		fmt.Println(usage(false))
		os.Exit(0)
	} else if args[0] == "help" {
		if len(args) == 2 {
			// add help for specific commands here
			fmt.Println(usage(true))
		} else {
			fmt.Println(usage(true))
		}
		os.Exit(0)
	}

	userJwt, err := getUserJwt(*userid, *baseUrl, *insecureSkipVerify)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	cli := Spartan{*baseUrl, *userid, *userJwt, *caPath, *insecureSkipVerify, *verbose}

	msg, err := cli.process(args)
	if err != nil {
		fmt.Println("**", err)
		os.Exit(1)
	} else {
		if msg != nil {
			fmt.Println(*msg)
		}
		os.Exit(0)
	}
}
