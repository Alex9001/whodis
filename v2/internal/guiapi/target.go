package guiapi

import (
	"github.com/Alex9001/whodis/v2"
)

func parseTarget(input string) (parseResult, error) {
	subject, err := whodis.ParseSubject(input, whodis.OperationRegistration)
	if err != nil {
		subject, err = whodis.ParseSubject(input, whodis.OperationDNSQuery)
		if err != nil {
			return parseResult{}, err
		}
	}
	return parseResult{Input: input, Normalized: subject.Canonical, Subject: subject}, nil
}
