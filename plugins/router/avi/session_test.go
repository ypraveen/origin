package avi

import (
	"testing"
	"log"
	"reflect"
	//"time"
)

func TestTest(t *testing.T) {
	avisess := NewAviSession("10.10.25.201", "admin", "avi123", true)
	avisess.InitiateSession()

	res, err := avisess.Get("api/tenant")
	log.Println("res: ", res, " err:", err)
	resp := res.(map[string]interface{})
	log.Println("count: ", resp["count"])

	// create a tenant
	tenant := make(map[string]string)
	tenant["name"] = "testtenant"
	res, err = avisess.Post("api/tenant", tenant)
	log.Println("res: ", res, " err:", err)
	if err != nil {
		log.Println("Tenant Creation failed: ", err)
		return
	}

	// check tenant is created well
	res, err = avisess.Get("api/tenant?name=testtenant")
	log.Println("res: ", res, " err:", err)
	if reflect.TypeOf(res).Kind() == reflect.String {
		t.Errorf("Got string instead of json!")
		return
	}
	resp = res.(map[string]interface{})
	log.Println("count: ", resp["count"])
	curr_count := resp["count"].(float64)
	if curr_count != 1.0 {
		t.Errorf("could not find a tenant with name testtenant")
		return
	}
	tenant["uuid"] = resp["results"].([]interface{})[0].(map[string]interface{})["uuid"].(string)

	// delete the tenant
	res, err = avisess.Delete("api/tenant/" + tenant["uuid"])
	log.Println("res: ", res, " err:", err)
	if err != nil {
		t.Error("Deletion failed")
		return
	}

	// check to make sure that the tenant is not there any more
	// check tenant is created well
	res, err = avisess.Get("api/tenant?name=testtenant")
	log.Println("res: ", res, " err:", err)
	resp = res.(map[string]interface{})
	log.Println("count: ", resp["count"])
	curr_count = resp["count"].(float64)
	if curr_count != 0.0 {
		t.Errorf("Expecting no tenant with that name")
		return
	}

	t.Error("Just to force output")
}
