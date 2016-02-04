package avi

import (
	"encoding/json"
	"fmt"
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

// checks if pool exists: returns the pool, else some error
func (p *AviPlugin) CheckPoolExists(poolname string) (bool, map[string]interface{}, error) {
	var resp map[string]interface{}

	cresp, err := p.AviSess.GetCollection("/api/pool?name=" + poolname)
	if err != nil {
		glog.V(4).Infof("Avi PoolExists check failed: %v", cresp)
		return false, resp, err
	}

	if cresp.Count == 0 {
		return false, resp, nil
	}
	nres, err := ConvertAviResponseToMapInterface(cresp.Results[0])
	if err != nil {
		return true, resp, err
	}
	return true, nres.(map[string]interface{}), nil
}

func (p *AviPlugin) CreatePool(poolname string) (map[string]interface{}, error) {
	var resp map[string]interface{}
	pool := make(map[string]string)
	pool["name"] = poolname
	pres, err := p.AviSess.Post("/api/pool", pool)
	if err != nil {
		glog.V(4).Infof("Error creating pool %s: %v", poolname, pres)
		return resp, err
	}
	return pres.(map[string]interface{}), nil
}

func (p *AviPlugin) EnsurePoolExists(poolname string) (map[string]interface{}, error) {
	exists, resp, err := p.CheckPoolExists(poolname)
	if exists || err != nil {
		return resp, err
	}
	return p.CreatePool(poolname)
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
	pool, err := p.EnsurePoolExists(poolname)
	if err != nil {
		return err
	}
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
	res, err := p.AviSess.Put("/api/pool/"+pool_uuid, pool)
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
	exists, pool, err := p.CheckPoolExists(poolname)
	if err != nil || !exists {
		glog.V(4).Infof("pool does not exist or can't obtain!: %v", pool)
		return err
	}
	pool_uuid := pool["uuid"].(string)

	res, err := p.AviSess.Delete("/api/pool/" + pool_uuid)
	if err != nil {
		glog.V(4).Infof("Error deleting pool %s: %v", poolname, res)
		return err
	}
	return nil
}

// deletePoolIfEmpty deletes the named pool from Avi if, and only if, it
// has no members.
func (p *AviPlugin) DeletePoolIfEmpty(poolname string) error {
	exists, pool, err := p.CheckPoolExists(poolname)
	if !exists || err != nil {
		glog.V(4).Infof("pool does not exist or can't obtain!: %v", pool)
		return err
	}

	members := getPoolMembers(pool)
	if len(members) == 0 {
		pool_uuid := pool["uuid"].(string)
		res, err := p.AviSess.Delete("/api/pool/" + pool_uuid)
		if err != nil {
			glog.V(4).Infof("Error deleting pool %s: %v", poolname, res)
			return err
		}
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

func (p *AviPlugin) GetVirtualService(vsname string) (map[string]interface{}, error) {
	resp := make(map[string]interface{})
	res, err := p.AviSess.GetCollection("/api/virtualservice?name=" + vsname)
	if err != nil {
		glog.V(4).Infof("Avi VS Exists check failed: %v", res)
		return resp, err
	}

	if res.Count == 0 {
		return resp, fmt.Errorf("Virtual Service %s does not exist on the Avi Controller",
			vsname)
	}
	nres, err := ConvertAviResponseToMapInterface(res.Results[0])
	if err != nil {
		glog.V(4).Infof("VS unmarshal failed: %v", string(res.Results[0]))
		return resp, err
	}
	return nres.(map[string]interface{}), nil
}

func (p *AviPlugin) GetResourceByName(resource, objname string) (map[string]interface{}, error) {
	resp := make(map[string]interface{})
	res, err := p.AviSess.GetCollection("/api/" + resource + "?name=" + objname)
	if err != nil {
		glog.V(4).Infof("Avi object exists check (res: %s, name: %s) failed: %v", resource, objname, res)
		return resp, err
	}

	if res.Count == 0 {
		return resp, fmt.Errorf("Resource name %s of type %s does not exist on the Avi Controller",
			objname, resource)
	}
	nres, err := ConvertAviResponseToMapInterface(res.Results[0])
	if err != nil {
		glog.V(4).Infof("Resource unmarshal failed: %v", string(res.Results[0]))
		return resp, err
	}
	return nres.(map[string]interface{}), nil
}

func (p *AviPlugin) EnsureHTTPPolicySetExists(routename, poolref, hostname,
	pathname string) (map[string]interface{}, error) {
	http_policy_set := make(map[string]interface{})
	res, err := p.AviSess.GetCollection("/api/httppolicyset?name=" + routename)
	if err != nil {
		glog.V(4).Infof("Avi HTTP Policy Set Exists check failed: %v", res)
		return http_policy_set, err
	}

	var nres interface{}
	if res.Count == 0 {
		jsonstr := `{
		"name": "%s",
		"http_request_policy": {
		  "rules": [{
		    "index": 1,
		    "enable": true,
		    "name": "%s",
		    "match": {
		      "path": {
		        "match_case": "INSENSITIVE",
		        "match_str": [{"str": "%s"}],
		        "match_criteria": "BEGINS_WITH"},
		      "host_hdr": {
		        "match_case": "INSENSITIVE",
		        "value": [{"str": "%s"}],
		        "match_criteria": "HDR_EQUALS"},
		      "vs_port": {
		        "match_criteria": "IS_IN",
		        "ports": [{"port": "80"}]}
		    },
		    "switching_action": {
		      "action": "HTTP_SWITCHING_SELECT_POOL",
		      "status_code": "HTTP_LOCAL_RESPONSE_STATUS_CODE_200",
		      "pool_ref": "%s"}
		  }]
		},
		"is_internal_policy": false}`
		jsonstr = fmt.Sprintf(jsonstr, routename, routename, pathname, hostname, poolref)
		json.Unmarshal([]byte(jsonstr), &http_policy_set)
		nres, err = p.AviSess.Post("/api/httppolicyset", http_policy_set)
		if err != nil {
			glog.V(4).Info("HTTP Policy Set creation failed: %v", nres)
			return http_policy_set, err
		}
	} else {
		nres, err = ConvertAviResponseToMapInterface(res.Results[0])
		if err != nil {
			glog.V(4).Info("Unmarshaling HTTP Policy Set failed: %v", string(res.Results[0]))
			return http_policy_set, err
		}
	}
	return nres.(map[string]interface{}), nil
}

func hash(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

func (p *AviPlugin) AddPolicySet(http_policy_set map[string]interface{}, routename string) error {
	vs, err := p.GetVirtualService(p.AviConfig.VSname)
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
			"index":               hash(routename) & 0x00ffffff,
			"http_policy_set_ref": http_policy_set["url"].(string),
		})
	res, err := p.AviSess.Put("/api/virtualservice/"+vs["uuid"].(string), vs)
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
	var http_policy_set map[string]interface{}
	cresp, err := p.AviSess.GetCollection("/api/httppolicyset?name=" + routename)
	if err != nil {
		glog.V(4).Infof("Avi HTTP Policy Set Exists check failed: %v", cresp)
		return err
	}

	if cresp.Count == 0 {
		glog.V(4).Infof("HTTP policy set does not exist!: %s", routename)
		return nil
	}
	iresp, err := ConvertAviResponseToMapInterface(cresp.Results[0])
	http_policy_set = iresp.(map[string]interface{})
	if err != nil {
		glog.V(4).Infof("Could not parse http policy for route %s: %s", routename, string(cresp.Results[0]))
		return err
	}

	vs, err := p.GetVirtualService(p.AviConfig.VSname)
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
			res, err := p.AviSess.Put("/api/virtualservice/"+vs["uuid"].(string), vs)
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

	iresp, err = p.AviSess.Delete("/api/httppolicyset/" + http_policy_set["uuid"].(string))
	if err != nil {
		return err
	}

	return nil
}

func (p *AviPlugin) UploadCertAndKey(certname, certdata, keydata string) error {
	ssl_cert, err :=  p.GetResourceByName("sslkeyandcertificate", certname)
	if err == nil {
		ssl_cert = ssl_cert["certificate"].(map[string]interface{})
		if ssl_cert["public_key"].(string) == keydata && ssl_cert["certificate"].(string) == certdata {
			glog.V(4).Infof("Certificate already exists %s", certname)
			return nil
		}
	}
	data := map[string]interface{}{
		"name": certname,
		"certificate": certdata,
		"key": keydata,
	}
	nres, err := p.AviSess.Post(
		"/api/sslkeyandcertificate/importkeyandcertificate",
		data,
	)
	if err != nil {
		glog.V(4).Infof("Upload failed: %v", nres)
		return err
	}
	return nil
}

func (p *AviPlugin) CreateChildVirtualService(routename, poolname, hostname, pathname, certname string) error {
	pool, err := p.EnsurePoolExists(poolname)
	if err != nil {
		return err
	}

	pvs, err := p.GetVirtualService(p.AviConfig.VSname)
	if err != nil {
		return err
	}

	app_profile, err := p.GetResourceByName("applicationprofile", "System-Secure-HTTP")
	if err != nil {
		return err
	}

	if len(certname) == 0 {
		certname = "System-Default-Cert"
	}
	ssl_cert, err :=  p.GetResourceByName("sslkeyandcertificate", certname)
	if err != nil {
		return err
	}

	cvs, err := p.GetVirtualService(routename)
	if err == nil {
		// check if the existing vs has the right cert
		if cvs["ssl_key_and_certificate_refs"].([]interface{})[0].(string) == ssl_cert["url"] {
			glog.V(4).Infof("VS already exists %s", certname)
			return  nil
		}
	}
	jsonstr := `{
       "uri_path":"/api/virtualservice",
       "model_name":"virtualservice",
       "data":{
         "network_profile_name":"System-TCP-Proxy",
         "flow_dist":"LOAD_AWARE",
         "delay_fairness":false,
         "avi_allocated_vip":false,
         "scaleout_ecmp":false,
         "analytics_profile_name":"System-Analytics-Profile",
         "cloud_type":"CLOUD_NONE",
         "weight":1,
         "cloud_name":"Default-Cloud",
         "avi_allocated_fip":false,
         "max_cps_per_client":0,
         "type":"VS_TYPE_VH_CHILD",
         "use_bridge_ip_as_vip":false,
         "application_profile_ref":"%s",
         "ign_pool_net_reach":true,
         "east_west_placement":false,
         "limit_doser":false,
         "ssl_sess_cache_avg_size":1024,
         "enable_autogw":true,
         "auto_allocate_ip":false,
         "enabled":true,
         "analytics_policy":{
           "client_insights":"ACTIVE",
           "metrics_realtime_update":{
             "duration":60,
             "enabled":false},
           "full_client_logs":{
             "duration":30,
             "enabled":false},
           "client_log_filters":[],
           "client_insights_sampling":{}
         },
         "vs_datascripts":[],
         "vh_domain_name":["%s"],
         "name":"%s",
         "vh_parent_vs_ref":"%s",
         "pool_ref":"%s",
         "ssl_key_and_certificate_refs":[
           "%s"
         ]
       }
	}`
	jsonstr = fmt.Sprintf(jsonstr, app_profile["url"], hostname, routename, pvs["url"],
		pool["url"], ssl_cert["url"])
	var vs interface{}
	json.Unmarshal([]byte(jsonstr), &vs)
	nres, err := p.AviSess.Post("/api/macro", vs)
	if err != nil {
		glog.V(4).Info("Child VS creation failed: %v", nres)
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
	tls *routeapi.TLSConfig, modify bool) error {
	glog.V(4).Infof("Adding route %s...", routename)

	// We will use prettyPathname for log output.
	prettyPathname := pathname
	if prettyPathname == "" {
		prettyPathname = "(any)"
	}

	if tls == nil || len(tls.Termination) == 0 {
		if modify == true {
			p.DeleteSecureRoute(routename)
		}
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
		if modify == true {
			p.DeleteInsecureRoute(routename)
		}
		glog.V(4).Infof("Adding secure route %s for pool %s,"+
			" hostname %s, pathname %s...",
			routename, poolname, hostname, pathname)
		var certname string
		if len(tls.Certificate) > 0 && len(tls.Key) > 0 {
			certname = routename
			err := p.UploadCertAndKey(certname, tls.Certificate, tls.Key)
			if err != nil {
				glog.V(4).Infof("Error adding certificate for route %s: %v",
					routename, err)
				return err
			}
		}

		err := p.CreateChildVirtualService(routename, poolname, hostname, pathname, certname)
		if err != nil {
			glog.V(4).Infof("Error creating child VS for secure route %s: %v",
				routename, err)
			return err
		}
	}

	return nil
}

// deleteRoute deletes the named route from Avi.
func (p *AviPlugin) deleteRoute(routename string) error {
	glog.V(4).Infof("Deleting route %s...", routename)

	// Start with the routes because we cannot delete the pool until we delete
	// any associated profiles and rules.
	_, err := p.GetVirtualService(routename)
	if err != nil {
		// must be an insecure route
		err := p.DeleteInsecureRoute(routename)
		if err != nil {
			glog.V(4).Infof("Error deleting insecure route %s: %s.", routename, err)
			return err
		}
	} else {
		// secure route: delete child VS first and then the certificate
		err := p.DeleteSecureRoute(routename)
		if err != nil {
			glog.V(4).Infof("Error deleting secure route %s: %s.", routename, err)
			return err
		}
	}
	return nil
}

func (p *AviPlugin) DeleteSecureRoute(routename string) error {
	// delete child VS
	pvs, err := p.GetVirtualService(routename)
	if err == nil {
		iresp, err := p.AviSess.Delete("/api/virtualservice/" + pvs["uuid"].(string))
		if err != nil {
			glog.V(4).Infof("Error deleting vs %s: resp: %s, err: %s.", routename, iresp, err)
		}
	}

	//delete cert if it exists
	ssl_cert, err :=  p.GetResourceByName("sslkeyandcertificate", routename)
	if err != nil {
		glog.V(4).Infof("Cert with name %s does not exist", routename)
		return nil
	}

	iresp, err := p.AviSess.Delete("/api/sslkeyandcertificate/" + ssl_cert["uuid"].(string))
	if err != nil {
		glog.V(4).Infof("Error deleting cert %s: resp: %s, err: %s.", routename, iresp, err)
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
		/*
		err := p.deleteRoute(routename)
		if err != nil {
			return err
		}

		// Ensure the pool exists in case we have been told to modify a route that
		// did not already exist.
		_, err = p.EnsurePoolExists(poolname)
		if err != nil {
			return err
		}*/

		err := p.addRoute(routename, poolname, hostname, pathname, route.Spec.TLS, true)
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

		err := p.addRoute(routename, poolname, hostname, pathname, route.Spec.TLS, false)
		if err != nil {
			return err
		}
	}

	glog.V(4).Infof("Done processing route %s.", routename)

	return nil
}
