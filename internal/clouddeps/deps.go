//go:build tools

// Package clouddeps pins the Cognito SDK module the Cognito backend
// will use (Entra goes through Graph REST and adds no module), so
// `go mod tidy` keeps it in go.mod before any code
// imports it. The tools build tag keeps the file out of builds and the
// coverage gate; the Cognito backend item deletes it once its package imports
// the module.
package clouddeps

import (
	_ "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)
