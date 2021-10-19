package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type fileJson struct {
	SecurityType string `json:"securityType"`
	File         string `json:"file"`
	Line         int    `json:"line"`
}

func isNotValidReportType(reportType string) bool {
	if reportType == "json" || reportType == "txt" {
		return false
	}
	return true
}

func main() {

	// os.Open() opens specific file in
	// read-only mode and this return
	// a pointer of type os.
	path := os.Args[1]
	reportType := os.Args[2]
	if isNotValidReportType(reportType) {
		fmt.Printf("[WARN] Not acceptable output format, choose json or txt.\n")
	}

	file, err := os.Open(path)
	fileExtension := filepath.Ext(path)
	crossSiteScripting := false
	var dataJson []fileJson

	if fileExtension == ".html" || fileExtension == ".js" {
		crossSiteScripting = true
	}

	if err != nil {
		log.Fatalf("failed to open selected file")
	}

	// The bufio.NewScanner() function is called in which the
	// object os.File passed as its parameter and this returns a
	// object bufio.Scanner which is further used on the
	// bufio.Scanner.Split() method.
	scanner := bufio.NewScanner(file)

	// The bufio.ScanLines is used as an
	// input to the method bufio.Scanner.Split()
	// and then the scanning forwards to each
	// new line using the bufio.Scanner.Scan()
	// method.
	scanner.Split(bufio.ScanLines)
	line := 1
	var controlSQL []string
	indexStatement := 0
	possibleLine := 0

	for scanner.Scan() {
		currentLine := scanner.Text()

		if crossSiteScripting && checkCrossSiteScripting(currentLine) {
			dataJson = addToJson(dataJson, path, line, "Cross site scripting")
		}

		dataJson = sensitiveDataExposure(currentLine, path, line, dataJson)
		controlSQL, indexStatement, possibleLine, dataJson = sqlInjection(currentLine, controlSQL, indexStatement, path, line, possibleLine, dataJson)

		line++
	}

	// The method os.File.Close() is called
	// on the os.File object to close the file
	file.Close()

	if reportType == "json" {
		generateJsonReport(dataJson)
	} else {
		generateTxtReport(dataJson)
	}

}

func checkCrossSiteScripting(textLine string) bool {
	match, _ := regexp.MatchString(`alert[(]['|"][\s\w&.\-!$@#%*():;><.,|=+_^~'"{\]}[\\\/]*['|"][)]`, strings.ToLower(textLine))
	return match
}

func sensitiveDataExposure(textLine string, path string, line int, json []fileJson) []fileJson {
	lineLower := strings.ToLower(textLine)
	match1, _ := regexp.MatchString(`checkmarx`, lineLower)
	match2, _ := regexp.MatchString(`hellman & friedman`, lineLower)
	match3, _ := regexp.MatchString(`\$1\.15b`, lineLower)

	if match1 && match2 && match3 {
		json = addToJson(json, path, line, "Sensitive data exposure")
	}

	return json
}

func sqlInjection(textLine string, control []string, indexStatement int, path string, line int, possibleLine int, json []fileJson) ([]string, int, int, []fileJson) {
	words := strings.Fields(textLine)
	var statements = [...]string{`"`, `select`, `where`, `%s`, `"`}
	startQuote, _ := regexp.Compile(`^"`)
	endQuote, _ := regexp.Compile(`"$`)
	hasSelect, _ := regexp.Compile(`select`)
	hasString, _ := regexp.Compile(`%s`)

	for _, value := range words {
		startsWithQuote := startQuote.MatchString(strings.ToLower(value))
		endWithQuote := endQuote.MatchString(strings.ToLower(value))

		matchSelect := hasSelect.MatchString(strings.ToLower(value))
		matchString := hasString.MatchString(strings.ToLower(value))

		if (len(control) == 0 && startsWithQuote) || len(control) == 0 && strings.ToLower(value) == statements[0] {
			control = append(control, statements[0])
			indexStatement++
			possibleLine = line

			if matchSelect {
				control = append(control, statements[indexStatement])
				indexStatement++
			}
			continue
		}

		if strings.ToLower(value) == statements[indexStatement] {
			control = append(control, statements[indexStatement])
			if len(control) == 5 {
				json = addToJson(json, path, possibleLine, "SQL injection")
				control = nil
				indexStatement = 0
				possibleLine = 0
			}
			indexStatement++
			continue
		}

		if endWithQuote || strings.ToLower(value) == statements[4] {
			if matchString {
				control = append(control, statements[3])
			}

			control = append(control, statements[4])

			if len(control) == 5 {
				json = addToJson(json, path, possibleLine, "SQL injection")
			}

			control = nil
			indexStatement = 0
			possibleLine = 0
		}
	}

	return control, indexStatement, possibleLine, json
}

func addToJson(json []fileJson, path string, line int, securityType string) []fileJson {
	json = append(json, fileJson{
		SecurityType: securityType,
		File:         path,
		Line:         line,
	})

	return json
}

func generateJsonReport(dataJson []fileJson) {
	data, _ := json.MarshalIndent(dataJson, "", " ")
	_ = ioutil.WriteFile("report.json", data, 0644)
}

func generateTxtReport(dataJson []fileJson) {
	var result string
	for _, value := range dataJson {
		result += "[" + value.SecurityType + "] in file " + value.File + " on line " + strconv.Itoa(value.Line) + "\n"
	}

	file, err := os.Create("report.txt")

	if err != nil {
		panic(err)
	}

	file.WriteString(result)
}
