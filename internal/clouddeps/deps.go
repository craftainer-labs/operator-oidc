//go:build tools

// Package clouddeps pins the cloud SDK modules the Cognito and Entra
// backends will use, so `go mod tidy` keeps them in go.mod before any code
// imports them. The tools build tag keeps the file out of builds and the
// coverage gate; the backend items delete it once their packages import
// these modules.
package clouddeps

import (
	_ "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)
