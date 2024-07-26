// Copyright 2021 IBM Corp
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/IBM-Cloud/bluemix-go"
	"github.com/IBM-Cloud/bluemix-go/authentication"
	"github.com/IBM-Cloud/bluemix-go/http"
	"github.com/IBM-Cloud/bluemix-go/rest"
	bxsession "github.com/IBM-Cloud/bluemix-go/session"
	"github.com/IBM-Cloud/power-go-client/clients/instance"
	"github.com/IBM-Cloud/power-go-client/ibmpisession"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/sirupsen/logrus"
	"io"
	"os"
	gohttp "net/http"
	"strings"
	"time"
)

// Replaced with:
//   -ldflags="-X main.version=$(git describe --always --long --dirty)"
var (
	version string = "undefined"
	release string = "undefined"
	shouldDebug bool = false
	log *logrus.Logger
)

const (
	// resource ID for Power Systems Virtual Server in the Global catalog.
	virtualServerResourceID = "f165dd34-3a40-423b-9d95-e90a23f724dd"
)

type User struct {
	ID         string
	Email      string
	Account    string
	cloudName  string `default:"bluemix"`
	cloudType  string `default:"public"`
	generation int    `default:"2"`
}

func fetchUserDetails(bxSession *bxsession.Session, generation int) (*User, error) {

	var bluemixToken string

	config := bxSession.Config
	user := User{}

	if strings.HasPrefix(config.IAMAccessToken, "Bearer") {
		bluemixToken = config.IAMAccessToken[7:len(config.IAMAccessToken)]
	} else {
		bluemixToken = config.IAMAccessToken
	}

	token, err := jwt.Parse(bluemixToken, func(token *jwt.Token) (interface{}, error) {
		return "", nil
	})
	if err != nil && !strings.Contains(err.Error(), "key is of invalid type") {
		return &user, err
	}

	claims := token.Claims.(jwt.MapClaims)
	if email, ok := claims["email"]; ok {
		user.Email = email.(string)
	}
	user.ID = claims["id"].(string)
	user.Account = claims["account"].(map[string]interface{})["bss"].(string)
	iss := claims["iss"].(string)
	if strings.Contains(iss, "https://iam.cloud.ibm.com") {
		user.cloudName = "bluemix"
	} else {
		user.cloudName = "staging"
	}
	user.cloudType = "public"
	user.generation = generation

	return &user, nil
}

func createPiSession (ptrApiKey *string, ptrServiceName *string, ptrServiceGUID *string) (*ibmpisession.IBMPISession, string, error) {

	var bxSession *bxsession.Session
	var tokenProviderEndpoint string = "https://iam.cloud.ibm.com"
	var err error
	var controllerSvc *resourcecontrollerv2.ResourceControllerV2

	bxSession, err = bxsession.New(&bluemix.Config{
		BluemixAPIKey:         *ptrApiKey,
		TokenProviderEndpoint: &tokenProviderEndpoint,
		Debug:                 false,
	})
	if err != nil {
		return nil, "", fmt.Errorf("Error bxsession.New: %v", err)
	}
	log.Printf("bxSession = %v\n", bxSession)

	tokenRefresher, err := authentication.NewIAMAuthRepository(bxSession.Config, &rest.Client{
		DefaultHeader: gohttp.Header{
			"User-Agent": []string{http.UserAgent()},
		},
	})
	if err != nil {
		return nil, "", fmt.Errorf("Error authentication.NewIAMAuthRepository: %v", err)
	}
	log.Printf("tokenRefresher = %v\n", tokenRefresher)
	err = tokenRefresher.AuthenticateAPIKey(bxSession.Config.BluemixAPIKey)
	if err != nil {
		return nil, "", fmt.Errorf("Error tokenRefresher.AuthenticateAPIKey: %v", err)
	}

	user, err := fetchUserDetails(bxSession, 2)
	if err != nil {
		return nil, "", fmt.Errorf("Error fetchUserDetails: %v", err)
	}

	var authenticator core.Authenticator = &core.IamAuthenticator{
		ApiKey: *ptrApiKey,
	}

	err = authenticator.Validate()
	if err != nil {
		return nil, "", fmt.Errorf("authenticator.Validate: %v", err)
	}

	// Instantiate the service with an API key based IAM authenticator
	controllerSvc, err = resourcecontrollerv2.NewResourceControllerV2(&resourcecontrollerv2.ResourceControllerV2Options{
		Authenticator: authenticator,
		ServiceName:   "cloud-object-storage",
		URL:           "https://resource-controller.cloud.ibm.com",
	})
	if err != nil {
		return nil, "", fmt.Errorf("Error resourcecontrollerv2.NewResourceControllerV2: %v", err)
	}

	var (
		serviceGuid string = ""
		regionID    string = ""
		listOptions *resourcecontrollerv2.ListResourceInstancesOptions
		resources   *resourcecontrollerv2.ResourceInstancesList
		perPage     int64 = 64
		moreData          = true
		nextURL     *string
	)

	listOptions = controllerSvc.NewListResourceInstancesOptions()
//	listOptions.SetResourceGroupID(si.resourceGroupID)
	listOptions.SetResourcePlanID(virtualServerResourceID)
	listOptions.SetLimit(perPage)

	for moreData {
		log.Debugf("listOptions = %+v", listOptions)

		resources, _, err = controllerSvc.ListResourceInstances(listOptions)
		if err != nil {
			log.Fatalf("Error: ListResourceInstancesWithContext returns %v", err)
			return nil, "", err
		}

		log.Debugf("resources.RowsCount = %v", *resources.RowsCount)

		for _, resource := range resources.Resources {
			var (
				getResourceOptions *resourcecontrollerv2.GetResourceInstanceOptions
				resourceInstance   *resourcecontrollerv2.ResourceInstance
				response           *core.DetailedResponse
			)

			getResourceOptions = controllerSvc.NewGetResourceInstanceOptions(*resource.ID)

			resourceInstance, response, err = controllerSvc.GetResourceInstance(getResourceOptions)
			if err != nil {
				log.Fatalf("Error: GetResourceInstance returns %v", err)
				return nil, "", err
			}
			if response != nil && response.StatusCode == gohttp.StatusNotFound {
				log.Debugf("gohttp.StatusNotFound")
				continue
			} else if response != nil && response.StatusCode == gohttp.StatusInternalServerError {
				log.Debugf("gohttp.StatusInternalServerError")
				continue
			}

			if resourceInstance.Type == nil || resourceInstance.GUID == nil {
				continue
			}
			if *resourceInstance.Type != "service_instance" && *resourceInstance.Type != "composite_instance" {
				continue
			}

			if *ptrServiceName != "" && *resource.Name == *ptrServiceName {
				log.Debugf("FOUNDBYNAME Name = %s", *resource.Name)
				serviceGuid = *resource.GUID
				regionID = *resource.RegionID
			} else if *ptrServiceGUID != "" && *resource.GUID == *ptrServiceGUID {
				log.Debugf("FOUNDBYGIUD Name = %s", *resource.Name)
				serviceGuid = *resource.GUID
				regionID = *resource.RegionID
			} else {
				log.Debugf("SKIP Name = %s", *resource.Name)
			}
		}

		// Based on: https://cloud.ibm.com/apidocs/resource-controller/resource-controller?code=go#list-resource-instances
		nextURL, err = core.GetQueryParam(resources.NextURL, "start")
		if err != nil {
			log.Fatalf("Error: GetQueryParam returns %v", err)
			return nil, "", err
		}
		if nextURL == nil {
			listOptions.SetStart("")
		} else {
			listOptions.SetStart(*nextURL)
		}

		moreData = *resources.RowsCount == perPage
	}
	if serviceGuid == "" {
		if *ptrServiceName != "" {
			return nil, "", fmt.Errorf("%s name not found in list of service instances!\n", *ptrServiceName)
		}
		if *ptrServiceGUID != "" {
			return nil, "", fmt.Errorf("%s GUID not found in list of service instances!\n", *ptrServiceGUID)
		}
		return nil, "", fmt.Errorf("Should not be here finding list of service instances!\n")
	}
	log.Printf("serviceGuid = %v\n", serviceGuid)

	authenticator = &core.IamAuthenticator{
		ApiKey: *ptrApiKey,
	}

	err = authenticator.Validate()
	if err != nil {
		return nil, "", fmt.Errorf("authenticator.Validate: %v", err)
	}

	var piSession *ibmpisession.IBMPISession
	var ibmpiOptions *ibmpisession.IBMPIOptions = &ibmpisession.IBMPIOptions{
		Authenticator: authenticator,
		Debug:         false,
		UserAccount:   user.Account,
		Zone:          regionID,
	}

	piSession, err = ibmpisession.NewIBMPISession(ibmpiOptions)
	if err != nil {
		return nil, "", fmt.Errorf("Error ibmpisession.New: %v", err)
	}
	log.Printf("piSession = %v\n", piSession)

	return piSession, serviceGuid, nil
}

func main() {

	var logMain *logrus.Logger = &logrus.Logger{
		Out: os.Stderr,
		Formatter: new(logrus.TextFormatter),
		Level: logrus.DebugLevel,
	}

	var ptrApiKey *string
	var ptrServiceName *string
	var ptrServiceGUID *string
	var ptrShouldDebug *string

	ptrApiKey = flag.String("apiKey", "", "Your IBM Cloud API key")
	ptrServiceName = flag.String("serviceName", "", "The cloud service to use")
	ptrServiceGUID = flag.String("serviceGUID", "", "The cloud service to use")
	ptrShouldDebug = flag.String("shouldDebug", "false", "Should output debug output")

	flag.Parse()

	if *ptrApiKey == "" {
		logMain.Fatal("Error: No API key set, use -apiKey")
	}

	if *ptrServiceName == "" && *ptrServiceGUID == "" {
		logMain.Fatal("Error: No cloud service set, use -serviceName or -serviceGUID")
	} else if *ptrServiceName != "" && *ptrServiceGUID != "" {
		logMain.Fatal("Error: Do not use both -serviceName and -serviceGUID together")
	}

	switch strings.ToLower(*ptrShouldDebug) {
	case "true":
		shouldDebug = true
	case "false":
		shouldDebug = false
	default:
		logMain.Fatalf("Error: shouldDebug is not true/false (%s)\n", *ptrShouldDebug)
	}

	var out io.Writer

	if shouldDebug {
		out = os.Stderr
	} else {
		out = io.Discard
	}
	log = &logrus.Logger{
		Out: out,
		Formatter: new(logrus.TextFormatter),
		Level: logrus.DebugLevel,
	}

	if shouldDebug { logMain.Printf("version = %v\nrelease = %v\n", version, release) }

	ctx, cancel := context.WithTimeout(context.TODO(), 2*time.Minute)
	defer cancel()

	var piSession *ibmpisession.IBMPISession
	var serviceGuid string
	var err error

	piSession, serviceGuid, err = createPiSession(ptrApiKey, ptrServiceName, ptrServiceGUID)
	if err != nil {
		logMain.Fatalf("Error createPiSession: %v\n", err)
	}

	systemPoolClient := instance.NewIBMPISystemPoolClient(ctx, piSession, serviceGuid)
	if shouldDebug { logMain.Printf("systemPoolClient = %v\n", systemPoolClient) }

	systemPools, err := systemPoolClient.GetSystemPools()
	if err != nil {
		logMain.Fatalf("Error systemPoolClient.GetSystemPools: %v\n", err)
	}
	if shouldDebug { logMain.Printf("systemPools = %v\n", systemPools) }

	var maxCoresAvailable float64
	var poolType string = "error"

	for _, systemPool := range systemPools {
		// https://github.com/IBM-Cloud/power-go-client/blob/master/power/models/system.go#L20
		// https://github.com/IBM-Cloud/power-go-client/blob/master/power/models/system_pool.go#L20

		// Helpful debug statement to save typing
		if shouldDebug {
			logMain.Printf("ValidateCapacityWithPools: pool %v, cores %v, memory %v\n", systemPool.Type, *systemPool.MaxCoresAvailable.Cores, *systemPool.MaxCoresAvailable.Memory)
		}

		if *systemPool.MaxCoresAvailable.Cores > maxCoresAvailable {
			poolType          = systemPool.Type
			maxCoresAvailable = *systemPool.MaxCoresAvailable.Cores
		}
	}
	if shouldDebug { logMain.Printf("poolType = %v, maxCoresAvailable = %v\n", poolType, maxCoresAvailable) }

	fmt.Printf("%v\n", poolType)
	os.Exit(0)
}
