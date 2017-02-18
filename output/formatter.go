// (c) Copyright 2016 Hewlett Packard Enterprise Development LP
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package output

import (
	"encoding/csv"
	"encoding/json"
	htmlTemplate "html/template"
	"io"
	"strconv"
	plainTemplate "text/template"

	gas "github.com/GoASTScanner/gas/core"
)

// CreateReport writes analysis report to w using the given data.
// The format of the report is set through format parameter
// It returns an error if report creation fails
func CreateReport(w io.Writer, format string, data *gas.Analyzer) error {
	var err error
	switch format {
	case "json":
		err = reportJSON(w, data)
	case "csv":
		err = reportCSV(w, data)
	case "html":
		err = reportFromHTMLTemplate(w, html, data)
	case "text":
		err = reportFromPlaintextTemplate(w, text, data)
	case "checkstyle":
		err = reportInCheckstyleFormat(w, data)
	default:
		err = reportFromPlaintextTemplate(w, text, data)
	}
	return err
}

func reportJSON(w io.Writer, data *gas.Analyzer) error {
	raw, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		panic(err)
	}

	_, err = w.Write(raw)
	if err != nil {
		panic(err)
	}
	return err
}

func reportCSV(w io.Writer, data *gas.Analyzer) error {
	out := csv.NewWriter(w)
	defer out.Flush()
	for _, issue := range data.Issues {
		err := out.Write([]string{
			issue.File,
			strconv.Itoa(issue.Line),
			issue.What,
			issue.Severity.String(),
			issue.Confidence.String(),
			issue.Code,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func reportFromPlaintextTemplate(w io.Writer, reportTemplate string, data *gas.Analyzer) error {
	t, e := plainTemplate.New("gas").Parse(reportTemplate)
	if e != nil {
		return e
	}

	return t.Execute(w, data)
}

func reportFromHTMLTemplate(w io.Writer, reportTemplate string, data *gas.Analyzer) error {
	t, e := htmlTemplate.New("gas").Parse(reportTemplate)
	if e != nil {
		return e
	}

	return t.Execute(w, data)
}

func reportInCheckstyleFormat(w io.Writer, data *gas.Analyzer) error {
	issues := aggregateIssues(data.Issues)
	t, e := plainTemplate.New("gas").Parse(checkstyleTemplate)
	if e != nil {
		return e
	}

	return t.Execute(w, issues)
}

// aggregateIssues groups issues by file to facilitate
// checkstyle XML report
func aggregateIssues(issues []*gas.Issue) map[string][]*gas.Issue {
	result := make(map[string][]*gas.Issue)
	var last string
	for _, is := range issues {
		if is.File != last {
			last = is.File
		}
		result[last] = append(result[last], is)
	}
	return result
}
