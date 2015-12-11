package avi

import (
	"testing"
	"log"
)

func TestTest(t *testing.T) {
	avisess := NewAviSession("10.10.25.201", "admin", "avi123", true)
	avisess.InitiateSession()

	res, err := avisess.Get("api/tenant")
	log.Println("res: ", res, " err:", err)
	t.Error("Just to force output")
}