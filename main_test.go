package main

import (
	"testing"
)

func TestCheckCrossSiteScriptingWithoutText(t *testing.T) {
	result := checkCrossSiteScripting("alert('')")
	if !result {
		t.Errorf("Cross site scripting didn't get, got: %v, want: %v", result, true)
	}
}

func TestCheckCrossSiteScriptingWithText(t *testing.T) {
	result := checkCrossSiteScripting("Alert(\"Lorem ipsum dolor sit amet\")")
	if !result {
		t.Errorf("Cross site scripting didn't get, got: %v, want: %v", result, true)
	}
}

func TestCheckCrossSiteScriptingDoesntExist(t *testing.T) {
	result := checkCrossSiteScripting("message('')")
	if result {
		t.Errorf("Cross site scripting didn't get, got: %v, want: %v", result, false)
	}
}

func TestCheckCrossSiteScriptingWrongFormat(t *testing.T) {
	result := checkCrossSiteScripting("alert('Lorem ipsum dolor)")
	if result {
		t.Errorf("Cross site scripting didn't get, got: %v, want: %v", result, false)
	}
}

func TestSensitiveDataExposureDoesntExist(t *testing.T) {
	var json []fileJson

	result := sensitiveDataExposure("Lorem ipsum dolor sit amet", "samples/sample.txt", 2, json)
	if len(result) > 0 {
		t.Errorf("Sensitive data exposure was incorrect, got: %v, want: %v", result, json)
	}
}

func TestSensitiveDataExposureExist(t *testing.T) {
	var expected = []fileJson{
		{
			SecurityType: "Sensitive data exposure",
			File:         "samples/sample.txt",
			Line:         1,
		},
	}

	var json []fileJson

	result := sensitiveDataExposure("Checkmarx test was good with Hellman & Friedman resulting in $1.15b dolars per month.", "samples/sample.txt", 1, json)
	if len(result) == 0 {
		t.Errorf("Sensitive data exposure was incorrect, got: %v, want: %v", result, expected)
	}
}

func TestSqlInjectionExists(t *testing.T) {
	var controlSQL []string
	indexStatement := 0
	possibleLine := 0
	var json []fileJson
	var result []fileJson

	var expected = []fileJson{
		{
			SecurityType: "SQL injection",
			File:         "samples/contact.ts",
			Line:         18,
		},
	}

	_, _, _, result = sqlInjection("\"SELECT * FROM Contact WHERE contactId IN UNNEST %s AND active \"", controlSQL, indexStatement, "samples/contact.ts", 18, possibleLine, json)

	if len(result) == 0 {
		t.Errorf("Sql Injection didn't get, got: %v, want: %v", result, expected)
	}
}

func TestSqlInjectionDoesntExist(t *testing.T) {
	var controlSQL []string
	indexStatement := 0
	possibleLine := 0
	var json []fileJson
	var result []fileJson

	_, _, _, result = sqlInjection("if ((contractId || []).length === 0) {", controlSQL, indexStatement, "samples/contact.ts", 18, possibleLine, json)

	if len(result) > 0 {
		t.Errorf("Sql Injection didn't get, got: %v, want: %v", result, json)
	}
}
