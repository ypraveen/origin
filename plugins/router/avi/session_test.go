package avi

import (
	"log"
	"reflect"
	"testing"
	"io/ioutil"
	routeapi "github.com/openshift/origin/pkg/route/api"
    //"time"
)

func TestAviSession(t *testing.T) {
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

	//t.Error("Just to force output")
}

func TestAviPluginPoolFunctions(t *testing.T) {
	avi, err := NewAviPlugin(AviPluginConfig{
		Host:     "10.10.25.201",
		Username: "admin",
		Password: "avi123",
		Cloudname: "Default-Cloud",
		Insecure: true,
	})
	if err != nil {
		t.Errorf("Creating plugin failed %s", err)
		return
	}
	_, err = avi.EnsurePoolExists("testpool")
	if err != nil {
		t.Errorf("Pool Creation failed %s", err)
		return
	}
	nmembers := make(map[string]int)
	nmembers["10.10.30.40"] = 80
	err = avi.UpdatePoolMembers("testpool", nmembers)
	if err != nil {
		t.Errorf("Pool update failed %s", err)
		return
	}
	nmembers["10.10.30.50"] = 80
	err = avi.UpdatePoolMembers("testpool", nmembers)
	if err != nil {
		t.Errorf("Pool update failed %s", err)
		return
	}
	err = avi.DeletePoolIfEmpty("testpool")
	exists, _, _ := avi.CheckPoolExists("testpool")
	if !exists {
		t.Errorf("Pool delete should have failed as it is not empty")
		return
	}
	err = avi.DeletePool("testpool")
	if err != nil {
		t.Errorf("Pool update failed %s", err)
		return
	}
	//t.Error("Just to force output")
}

func TestAviPlugin(t *testing.T) {
	avi, err := NewAviPlugin(AviPluginConfig{
		Host:     "10.10.25.201",
		Username: "admin",
		Password: "avi123",
		Insecure: true,
		Cloudname: "Default-Cloud",
		VSname:   "openshift_router",
	})
	if err != nil {
		t.Errorf("Creating plugin failed %s", err)
		return
	}
	err = avi.AddInsecureRoute("test", "test", "test.com", "")
	if err != nil {
		t.Errorf("Creating insecure route failed %s", err)
		return
	}
	err = avi.DeleteInsecureRoute("test")
	if err != nil {
		t.Errorf("Deleting insecure route failed %s", err)
		return
	}
	//t.Error("Just to force output")
}

func TestSecureRoutes(t *testing.T) {
	avi, err := NewAviPlugin(AviPluginConfig{
		Host:     "10.10.25.201",
		Username: "admin",
		Password: "avi123",
		Cloudname: "Default-Cloud",
		Insecure: true,
		VSname:   "openshift_router",
	})
	if err != nil {
		t.Errorf("Creating plugin failed %s", err)
		return
	}
	certdata, err := ioutil.ReadFile("./certs/acert")
	keydata, err := ioutil.ReadFile("./certs/akey")
	tls := routeapi.TLSConfig{
		Termination: routeapi.TLSTerminationEdge,
		CACertificate: string(certdata),
		Key: string(keydata),
	}
	err = avi.addRoute("test", "test", "test.com", "", &tls, true)
	if err != nil {
		t.Errorf("Adding secure route failed %s", err)
		return
	}
	err = avi.deleteRoute("test")
	if err != nil {
		t.Errorf("Deleting secure route failed %s", err)
		return
	}
	//t.Error("Just to force output")
}
