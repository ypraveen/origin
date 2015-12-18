package avi

import (
	"fmt"

	"github.com/golang/glog"
	kapi "k8s.io/kubernetes/pkg/api"
	//"k8s.io/kubernetes/pkg/util/sets"
	//"k8s.io/kubernetes/pkg/watch"

	//routeapi "github.com/openshift/origin/pkg/route/api"
	"reflect"
)

// AviPlugin holds state for the avi plugin.
type AviPlugin struct {
	// AviSess is the object that keeps a session with Avi Controller
	AviSess *AviSession
}

// AviPluginConfig holds configuration for the avi plugin.
type AviPluginConfig struct {
	// Host specifies the hostname or IP address of the Avi Controller.
	Host string

	// username specifies the username with which we should authenticate with the
	// Avi Controller.
	Username string

	// password specifies the password with which we should authenticate with the
	// Avi Controller.
	Password string

	// insecure specifies whether we should perform strict certificate validation
	// for connections to the Avi Controller.
	Insecure bool
}

// NewAviPlugin makes a new avi router plugin.
func NewAviPlugin(cfg AviPluginConfig) (*AviPlugin, error) {
	avisess := NewAviSession(cfg.Host, cfg.Username, cfg.Password, cfg.Insecure)
	return &AviPlugin{AviSess: avisess}, avisess.InitiateSession()
}

type AviResult struct {
	count int
	results []map[string]interface{}
}

func convertAviResponseToAviResult(res interface{}) *AviResult {
	resp := res.(map[string]interface{})
	_results := resp["results"].([]interface{})
	results := make([]map[string]interface{}, 0)
	for _, res := range _results{
		results = append(results, res.(map[string]interface{}))
	}
	return &AviResult{
		count: int(resp["count"].(float64)),
		results: results,
	}
}

// ensurePoolExists checks whether the named pool already exists in Avi
// and creates it if it does not.
func (p *AviPlugin) EnsurePoolExists(poolname string) error {
	res, err := p.AviSess.Get("/api/pool?name=" + poolname)
	if err != nil {
		glog.V(4).Infof("Avi PoolExists check failed: %v", res)
		return err
	}
	avires := convertAviResponseToAviResult(res)

	if avires.count == 0 {
		pool := make(map[string]string)
		pool["name"] = poolname
		res, err = p.AviSess.Post("/api/pool", pool)
		if err != nil {
			glog.V(4).Infof("Error creating pool %s: %v", poolname, res)
			return err
		}
	}

	return nil
}

func getPoolMembers(pool interface{}) map[string]int {
	members := make(map[string]int)
	pooldict := pool.(map[string]interface{})
	if pooldict["servers"] == nil {
		return members
	}
	_servers := pooldict["servers"].([]interface{})
	servers := make([]map[string]interface{}, 0)
	for _, server := range _servers {
		servers = append(servers, server.(map[string]interface{}))
	}
	defport := int(pooldict["default_server_port"].(float64))
	serverport := defport
	for _, server := range servers {
		serverport = defport
		if server["port"] != nil {
			serverport = int(server["port"].(float64))
		}
		members[server["ip"].(map[string]string)["addr"]] = serverport
	}
	return members
}

// updatePool update the named pool (which must already exist in Avi) with
// the given endpoints.
func (p *AviPlugin) UpdatePoolMembers(poolname string, new_members map[string]int) error {
	res, err := p.AviSess.Get("/api/pool?name=" + poolname)
	if err != nil {
		glog.V(4).Infof("Avi GetPool failed: %v", res)
		return err
	}
	glog.Errorf("pool -- res: %s", res)
	poolres := convertAviResponseToAviResult(res)
	pool := poolres.results[0]
	glog.Errorf("pool: %s", pool)
	current_members := getPoolMembers(pool)

	if reflect.DeepEqual(current_members, new_members) {
		glog.V(4).Infof("New members same as the existing members!")
		return nil
	}

	// new members not same as the old one; just do a new pool update with new members
	pool_uuid := pool["uuid"].(string)
	nmembers := make([]interface{}, 0)
	for memberip, memberport := range new_members {
		server := make(map[string]interface{})
		ip := make(map[string]interface{})
		ip["type"] = "V4"
		ip["addr"] = memberip
		server["ip"] = ip
		server["port"] = memberport
		nmembers = append(nmembers, server)
		glog.Errorf("nmbers in loop: %s", nmembers)
	}
	pool["servers"] = nmembers
	glog.Errorf("pool after assignment: %s", pool)
	res, err = p.AviSess.Put("/api/pool/" + pool_uuid, pool)
	if err != nil {
		glog.V(4).Infof("Avi update Pool failed: %v", res)
		return err
	}
	return nil
}


func (p *AviPlugin) UpdatePool(poolname string, endpoints *kapi.Endpoints) error {
	new_members := make(map[string]int)
	for _, subset := range endpoints.Subsets {
		for _, addr := range subset.Addresses {
			for _, port := range subset.Ports {
				new_members[addr.IP] = port.Port
			}
		}
	}

	return p.UpdatePoolMembers(poolname, new_members)
}

// deletePool delete the named pool from Avi.
func (p *AviPlugin) DeletePool(poolname string) error {
	res, err := p.AviSess.Get("/api/pool?name=" + poolname)
	if err != nil {
		glog.V(4).Infof("Avi PoolExists check failed: %v", res)
		return err
	}
	poolres := convertAviResponseToAviResult(res)

	if poolres.count == 0 {
		glog.V(4).Infof("pool does not exist!: %v", res)
		return nil
	}
	glog.Errorf("pool: %s", poolres)
	pool := poolres.results[0]
	pool_uuid := pool["uuid"].(string)

	res, err = p.AviSess.Delete("/api/pool/" + pool_uuid)
	if err != nil {
		glog.V(4).Infof("Error deleting pool %s: %v", poolname, res)
		return err
	}
	return nil
}



// deletePoolIfEmpty deletes the named pool from Avi if, and only if, it
// has no members.
func (p *AviPlugin) DeletePoolIfEmpty(poolname string) error {
	res, err := p.AviSess.Get("/api/pool?name=" + poolname)
	if err != nil {
		glog.V(4).Infof("Avi PoolExists check failed: %v", res)
		return err
	}
	poolres := convertAviResponseToAviResult(res)

	if poolres.count == 0 {
		glog.V(4).Infof("pool does not exist!: %v", res)
		return nil
	}

	members := getPoolMembers(poolres.results[0])
	if len(members) == 0 {
		return p.DeletePool(poolname)
	}
	return nil
}

// poolName returns a string that can be used as a poolname in Avi and
// is distinct for the given endpoints namespace and name.
func poolName(endpointsNamespace, endpointsName string) string {
	return fmt.Sprintf("openshift_%s_%s", endpointsNamespace, endpointsName)
}

