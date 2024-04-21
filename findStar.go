package main

import (
	"strings"

	"github.com/Jeffail/gabs/v2"
)

// the starting function is IsAsteriskFree

/*
Check if there's an asterisk (*) in any Resource field in the given JSON AWS::IAM::Role Policy.
Return false if there is, true in any other case.
*/
func IsAsteriskFree(jsonString string) bool {
	jsonParsed := parseJSON(jsonString)

	gObj, err := jsonParsed.JSONPointer("/PolicyDocument/Statement")
	if err != nil {
		return true // there's no Statement
	}

	switch gObj.Data().(type) {
	case []interface{}: // value of Statement is an array
		for _, statement := range gObj.Children() {
			if statementHasAsterisk(statement) {
				return false
			}
		}

	case map[string]interface{}: // value of Statement is an object
		return !statementHasAsterisk(gObj)

	default:
		panic(`Value of "Statement" is neither a JSON object nor an array.`)
	}

	return true
}

/*
Checks all Resource fields in a given Statement JSON object for asterisks (*).
Returns true if it finds any asterisks, false otherwise.
*/
func statementHasAsterisk(statement *gabs.Container) bool {
	gObj, err := statement.JSONPointer("/Resource")
	if err != nil {
		return false // there's no Resource
	}

	switch gObj.Data().(type) {
	case []interface{}: // value of Resource is an array
		for _, resource := range gObj.Children() {
			if resourceHasAsterisk(resource) {
				return true
			}
		}

	case string: // value of Resource is a string
		return resourceHasAsterisk(gObj)

	default:
		panic(`Value of "Resource" is neither a string nor an array.`)
	}

	return false
}

/*
Checks if the given Resource string has any asterisks (*).
Returns true if it does, false otherwise.
*/
func resourceHasAsterisk(resource *gabs.Container) bool {
	str, isString := resource.Data().(string)

	if !isString {
		panic("Resource is not a string.")
	}

	return strings.Contains(str, "*")
}

/*
Parses a given JSON object string using the gabs library.
*/
func parseJSON(jsonString string) *gabs.Container {
	jsonParsed, err := gabs.ParseJSON([]byte(jsonString))

	if err != nil {
		panic(err)
	}

	return jsonParsed
}
