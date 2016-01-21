package avi

import (
	"fmt"
	"encoding/json"
	"hash/fnv"

	"github.com/golang/glog"
	kapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/util/sets"
	"k8s.io/kubernetes/pkg/watch"

	routeapi "github.com/openshift/origin/pkg/route/api"
	"reflect"
)

// AviPlugin holds state for the avi plugin.
type AviPlugin struct {
	// AviSess is the object that keeps a session with Avi Controller
	AviSess *AviSession

	// plugin config
	AviConfig AviPluginConfig
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

	// virtual service to use for managing routes
	VSname string
}

// NewAviPlugin makes a new avi router plugin.
func NewAviPlugin(cfg AviPluginConfig) (*AviPlugin, error) {
	avisess := NewAviSession(cfg.Host, cfg.Username, cfg.Password, cfg.Insecure)
	return &AviPlugin{AviSess: avisess, AviConfig: cfg}, avisess.InitiateSession()
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
func (p *AviPlugin) EnsurePoolExists(poolname string) (map[string]interface{}, error) {
	resp := make(map[string]interface{})
	res, err := p.AviSess.Get("/api/pool?name=" + poolname)
	if err != nil {
		glog.V(4).Infof("Avi PoolExists check failed: %v", res)
		return resp, err
	}
	avires := convertAviResponseToAviResult(res)

	if avires.count == 0 {
		pool := make(map[string]string)
		pool["name"] = poolname
		res, err = p.AviSess.Post("/api/pool", pool)
		if err != nil {
			glog.V(4).Infof("Error creating pool %s: %v", poolname, res)
			return resp, err
		}
	} else {
		res = avires.results[0]
	}

	return res.(map[string]interface{}), nil
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
		members[server["ip"].(map[string]interface{})["addr"].(string)] = serverport
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

// HandleEndpoints processes watch events on the Endpoints resource and
// creates and deletes pools and pool members in response.
func (p *AviPlugin) HandleEndpoints(eventType watch.EventType,
	endpoints *kapi.Endpoints) error {

	glog.V(4).Infof("Processing %d Endpoints for Name: %v (%v)",
		len(endpoints.Subsets), endpoints.Name, eventType)

	for i, s := range endpoints.Subsets {
		glog.V(4).Infof("  Subset %d : %#v", i, s)
	}

	switch eventType {
	case watch.Added, watch.Modified:
		// Name of the pool in Avi.
		poolname := poolName(endpoints.Namespace, endpoints.Name)

		if len(endpoints.Subsets) == 0 {
			// Avi does not permit us to delete a pool if it has a rule associated with
			// it.  However, a pool does not necessarily have a rule associated with
			// it because it may be from a service for which no route was created.
			// Thus we first delete the endpoints from the pool, then we try to delete
			// the pool, in case there is no route associated, but if there *is*
			// a route associated though, the delete will fail and we will have to
			// rely on HandleRoute to delete the pool when it deletes the route.

			glog.V(4).Infof("Deleting endpoints for pool %s", poolname)

			err := p.UpdatePool(poolname, endpoints)
			if err != nil {
				return err
			}

			glog.V(4).Infof("Deleting pool %s", poolname)

			err = p.DeletePool(poolname)
			if err != nil {
				return err
			}
		} else {
			glog.V(4).Infof("Updating endpoints for pool %s", poolname)

			_, err := p.EnsurePoolExists(poolname)
			if err != nil {
				return err
			}

			err = p.UpdatePool(poolname, endpoints)
			if err != nil {
				return err
			}
		}
	}

	glog.V(4).Infof("Done processing Endpoints for Name: %v.", endpoints.Name)

	return nil
}

// routeName returns a string that can be used as a rule name in F5 BIG-IP and
// is distinct for the given route.
func routeName(route routeapi.Route) string {
	return fmt.Sprintf("openshift_route_%s_%s", route.Namespace, route.Name)
}

func (p *AviPlugin) GetVirtualService() (map[string]interface{}, error) {
	resp := make(map[string]interface{})
	res, err := p.AviSess.Get("/api/virtualservice?name=" + p.AviConfig.VSname)
	if err != nil {
		glog.V(4).Infof("Avi VS Exists check failed: %v", res)
		return resp, err
	}
	avires := convertAviResponseToAviResult(res)

	if avires.count == 0 {
		return resp, fmt.Errorf("Virtual Service %s needs to be created on Avi Controller first",
			p.AviConfig.VSname)
	}
	return avires.results[0], nil
}

func (p *AviPlugin) EnsureHTTPPolicySetExists(routename, poolref, hostname,
    pathname string) (map[string]interface{}, error) {
	http_policy_set := make(map[string]interface{})
	res, err := p.AviSess.Get("/api/httppolicyset?name=" + routename)
	if err != nil {
		glog.V(4).Infof("Avi HTTP Policy Set Exists check failed: %v", res)
		return http_policy_set, err
	}
	avires := convertAviResponseToAviResult(res)

	if avires.count == 0 {
		jsonstr := `{
		"name": "%s",
		"http_request_policy": {"rules": [{"index": 1, "enable": true,
		"name": "%s", "match": {"path": {"match_case": "INSENSITIVE",
		"match_str": [{"str": "%s"}], "match_criteria": "BEGINS_WITH"},
		"host_hdr": {"match_case": "INSENSITIVE",
		"value": [{"str": "%s"}], "match_criteria": "HDR_EQUALS"}},
		"switching_action": {"action": "HTTP_SWITCHING_SELECT_POOL",
		"status_code": "HTTP_LOCAL_RESPONSE_STATUS_CODE_200",
		"pool_ref": "%s"}}]}, "is_internal_policy": false
		}`
		jsonstr = fmt.Sprintf(jsonstr, routename, routename, pathname, hostname, poolref)
		json.Unmarshal([]byte(jsonstr), &http_policy_set)
		res, err = p.AviSess.Post("/api/httppolicyset", http_policy_set)
		if err != nil {
			glog.V(4).Info("HTTP Policy Set creation failed: %v", res)
			return http_policy_set, err
		}
		http_policy_set = res.(map[string]interface{})
	} else {
		http_policy_set = avires.results[0]
	}
	return http_policy_set, nil
}

func hash(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

func (p *AviPlugin) AddPolicySet(http_policy_set map[string]interface{}, routename string) error {
	vs, err := p.GetVirtualService()
	if err != nil {
		return err
	}
	if vs["http_policies"] != nil {
		// check if policy is already there
		for _, hps := range vs["http_policies"].([]interface{}) {
			if hps.(map[string]interface{})["http_policy_set_ref"] == http_policy_set["url"].(string) {
				glog.V(4).Info("HTTP Policy Set already present in vs: %s", routename)
				return nil
			}
		}
	} else {
		vs["http_policies"] = make([]interface{}, 0)
	}

	vs["http_policies"] = append(vs["http_policies"].([]interface{}),
	                      map[string]interface{}{
							  "index": hash(routename) & 0xffffff,
							  "http_policy_set_ref": http_policy_set["url"].(string),
						  })
	res, err := p.AviSess.Put("/api/virtualservice/" + vs["uuid"].(string), vs)
	if err != nil {
		glog.V(4).Info("HTTP Policy Set addition to vs failed: %v", res)
		return err
	}

	return nil
}

func (p *AviPlugin) AddInsecureRoute(routename, poolname, hostname, pathname string) error {
	pool, err := p.EnsurePoolExists(poolname)
	if err != nil {
		return err
	}

	// create a new http policy set for this vs
	http_policy_set, err := p.EnsureHTTPPolicySetExists(routename, pool["url"].(string),
		hostname, pathname)
	if err != nil {
		return err
	}
	// add the policy set under vs's http policies
	return p.AddPolicySet(http_policy_set, routename)
}

func (p *AviPlugin) DeleteInsecureRoute(routename string) error {

	http_policy_set := make(map[string]interface{})
	res, err := p.AviSess.Get("/api/httppolicyset?name=" + routename)
	if err != nil {
		glog.V(4).Infof("Avi HTTP Policy Set Exists check failed: %v", res)
		return err
	}
	avires := convertAviResponseToAviResult(res)

	if avires.count == 0 {
		glog.V(4).Infof("HTTP policy set does not exist!: %s", routename)
		return nil
	}
	http_policy_set = avires.results[0]

	vs, err := p.GetVirtualService()
	if err != nil {
		return err
	}
	if vs["http_policies"] != nil {
		found := false
		new_policies := make([]interface{}, 0)
		for _, hps := range vs["http_policies"].([]interface{}) {
			if hps.(map[string]interface{})["http_policy_set_ref"] == http_policy_set["url"].(string) {
				found = true
			} else {
				new_policies = append(new_policies, hps)
			}
		}
		if found == true {
			vs["http_policies"] = new_policies
			res, err := p.AviSess.Put("/api/virtualservice/" + vs["uuid"].(string), vs)
			if err != nil {
				glog.V(4).Info("HTTP Policy Set addition to vs failed: %v", res)
				return err
			}
		} else {
			glog.V(4).Infof("HTTP policy set is not in use on VS: %s", routename)
		}
	} else {
		glog.V(4).Infof("VS policy set is empty: %s", routename)
	}

	res, err = p.AviSess.Delete("/api/httppolicyset/" + http_policy_set["uuid"].(string))
	if err != nil {
		return err
	}

	return nil
}

func (p *AviPlugin) AddSecureRoute(routename, poolname, hostname, pathname string) error {
	return nil
}

// In order to map OpenShift routes to Avi objects, we must divide routes into
// several types:
//
// • "Insecure" routes, those with no SSL/TLS, are implemented using a profile
//   on the one vserver by creating a rule for each route.
//
// • "Secure" routes, comprising edge and reencrypt routes, are implemented
//   using SNI if certificate is present, otherwise we would just use another
//   rule
//
// • "Passthrough" routes are not implemented yet

// addRoute creates route with the given name and parameters and of the suitable
// type (insecure or secure) based on the given TLS configuration.
func (p *AviPlugin) addRoute(routename, poolname, hostname, pathname string,
	tls *routeapi.TLSConfig) error {
	glog.V(4).Infof("Adding route %s...", routename)

	// We will use prettyPathname for log output.
	prettyPathname := pathname
	if prettyPathname == "" {
		prettyPathname = "(any)"
	}

	if tls == nil || len(tls.Termination) == 0 {
		glog.V(4).Infof("Adding insecure route %s for pool %s,"+
			" hostname %s, pathname %s...",
			routename, poolname, hostname, prettyPathname)
		err := p.AddInsecureRoute(routename, poolname, hostname, pathname)
		if err != nil {
			glog.V(4).Infof("Error adding insecure route for pool %s: %v", poolname,
				err)
			return err
		}

	} else if tls.Termination == routeapi.TLSTerminationPassthrough {
		glog.V(4).Infof("Not supported yet")
	} else {
		glog.V(4).Infof("Not supported yet")
		glog.V(4).Infof("Adding secure route %s for pool %s,"+
			" hostname %s, pathname %s...",
			routename, poolname, hostname, pathname)
		return nil
	}

	return nil
}

// deleteRoute deletes the named route from Avi.
func (p *AviPlugin) deleteRoute(routename string) error {
	glog.V(4).Infof("Deleting route %s...", routename)

	// Start with the routes because we cannot delete the pool until we delete
	// any associated profiles and rules.

	err := p.DeleteInsecureRoute(routename)
	if err != nil {
		glog.V(4).Infof("Error deleting insecure route %s: %s.", routename, err)
		return err
	}
	return nil
}

func (p *AviPlugin) HandleNamespaces(namespaces sets.String) error {
	return fmt.Errorf("namespace limiting for Avi is not yet implemented")
}

// HandleRoute processes watch events on the Route resource and
// creates and deletes policy rules in response.
func (p *AviPlugin) HandleRoute(eventType watch.EventType,
	route *routeapi.Route) error {
	glog.V(4).Infof("Processing route for service: %v (%v)",
		route.Spec.To.Name, route)

	// Name of the pool in Avi.
	poolname := poolName(route.Namespace, route.Spec.To.Name)

	// Virtual hostname for policy rule in Avi.
	hostname := route.Spec.Host

	// Pathname for the policy rule in Avi.
	pathname := route.Spec.Path

	// Name for the route in Avi.
	routename := routeName(*route)

	switch eventType {
	case watch.Modified:
		glog.V(4).Infof("Updating route %s...", routename)

		err := p.deleteRoute(routename)
		if err != nil {
			return err
		}

		// Ensure the pool exists in case we have been told to modify a route that
		// did not already exist.
		_, err = p.EnsurePoolExists(poolname)
		if err != nil {
			return err
		}

		err = p.addRoute(routename, poolname, hostname, pathname, route.Spec.TLS)
		if err != nil {
			return err
		}

	case watch.Deleted:

		err := p.deleteRoute(routename)
		if err != nil {
			return err
		}

		err = p.DeletePoolIfEmpty(poolname)
		if err != nil {
			return err
		}

	case watch.Added:

		err := p.addRoute(routename, poolname, hostname, pathname, route.Spec.TLS)
		if err != nil {
			return err
		}
	}

	glog.V(4).Infof("Done processing route %s.", routename)

	return nil
}
