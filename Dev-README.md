# Hidden Bridge Development
Hidden Bridge plugins support an API that allows custom behavior for:
* Directly proxying data to another server without interception
* Handling and customizing requests
* HTTP proxying requests to a remote server 
* Handling and customizing responses from a remote server
* Returning custom responses without forwarding the request
* Custom TLS certificate handling  

It also supports a flexible ```Options``` configuration framework that allows for easy parsing, bundling and passing around configuration for different plugins and the system.

## Configuration
Configuration is stored in an ```Options``` struct type. It's underlying structure is: ```map[string]string``` but it has methods that allow different types of data to be stored and retrieved

### YAML Configuration
YAML configuration files are supported by ```Options``` with some minor caveats:
* Multiple root sections can be defined with a top-level dictionary
  ```
  ---
    proxy_server:
    proxy_plugins:
  ```

Each section can then define almost arbitrary key/value pairs:
* Values can be:
    * Null, empty or missing
    * Integers
    * Strings
    * List of integers
    * List of strings
* No nesting
    * Same concept can be achieved with dot notation in the key name

#### Example
proxy_plugins:
  githubcom:
    hosts:
      - github.com
    ports.https:
      - 9000
    ports.http:
      - 9001
    host.real: "https://github.com:443"
    host.real.proxy: "http://192.168.226.134:8888"

#### Required key/values
Each plugin must provide the following under ```proxy_plugins``` section:

```plugin_name:``` The name of the plugin. This MUST be the same as that in the plugin's source file

Under ```plugin_name```:
* ```hosts``` The list of hosts that this plugin will handle
* ```ports.https``` The list of secure/TLS/HTTPS ports that this plugin should accept requests on
    * These ports tell Hidden Bridge which ports to bind to and listen on for secure TLS connections
* ```ports.http``` The list of insecure/HTTP ports that this plugin should accept requests on
    * These ports tell Hidden Bridge which ports to bind to and listen on for insecure, plain HTTP connections

* **NOTE** Multiple plugins can "listen" on the same ports. Hidden Bridge will resolve the handler plugin by host name.

* **NOTE** Hidden Bridge uses the request's ```SNI``` information for TLS or ```Host``` header for HTTP and picks a suitable handler plugin purely from a matching ```hosts``` entry. It's the responsibility of the plugin to verify that the request is being made from a connection on an acceptable port, i.e. HTTPS requests from one of its ```ports.https``` or for HTTP requests, one of its  ```ports.http```

### Command Line flags
Command line flags are supported by ```Options``` with some minor caveates
* Key names (flags) start with a "-" on the command line, but are stripped in ```Options```
* All values are parsed as strings and follow a flag 
* Keys (flags) can be repeated, this will generate a list of values associated with the key (flag)

#### Example
```
-config config.yml -v debug
```

#### Required Flags
```-config``` must be provided and its value must point to a valid YAML config file

```-v``` is the level of output and is aptional


### ```Options``` API
* ```FromMap()``` Will take a ```map[string]interface{}``` and return an ```Options``` instance
  * Used to take a parsed YAML file and generate ```Options```
* Command line parsing is done internally within ```Options```
    * You define a flag set, using the same API as the ```std flag```, however the type is ```CliFlag(name, usage striing)```
    * You parse the command line options with ```CliParse(args []string)``` which returns an ```Options``` instance


## Global Initialization
At a minimum 
```
const (
	// pluginName represents the name of the plugin and should be declared
    // near the top of the source file
    pluginName = "<plugin name>"
)

type PluginHandler struct {
	plugins.BasePlugin
}

// init is the global init function and at a minimum the below should be 
// incldued
func init() {
	plugins.PluginBuilder[pluginName] = func() plugins.Plugin {
		u := PluginHandler{}
		u.Name_ = pluginName
		return &u
	}
}
```

## Plugin API
There are a number of "hooks" into the request/response handling of Hidden Bridge that allow a plugin to completely customize how a request is processed and how the repsonse is generated.

Each API function is optional to implment. A base plugin implementation, that should be included within the implementation of the custom plugin includes sensible default implementations of all of the API. Thus only the behavior that needs customizing needs to be implemented, overriding the base.

The API is:
* Name() string
* Init(opts *options.OptionValue) error
* String() string
* Ports(bool) []string
* HandlesURL(hostURL *url.URL) bool
* RemoteURL(hostURL *url.URL) (*url.URL, error)
* ProxyURL(hostURL *url.URL) (*url.URL, error)
* HandleCertificate(site string) (*tls.Certificate, error)
* HandleRequest(reqURL *url.URL, req *http.Request) (*url.URL, error)
* HandleResponse(reqURL *url.URL, resp *http.Response) error

### ```Name()```
This function should not be re-implmented instead:
```
const (
	pluginName = "<plugin name>"
)
```
Should be used near the top of the plugins source file. The initialization code (above) will automatically include this name in the instance. The base of implementation ```Name()``` will use this value.

### ```Init()```
Init should generally not have to be re-implemented as the base implementation does the majority of what's required. If custom initialization of the plugin is required, make sure that you also call ```Init()``` on the base implementation

#### Example
```
func (p *PluginHandler) Init(opts *options.OptionValue) error {
    // Do custom initialization here
    // ...

    // Initialize the base plugin implementation
	if err := p.BasePlugin.Init(opts); err != nil {
		return xerrors.Errorf("%s plugin failed to initialize: %w", 
            p.Name_, err)
	}

    // Possibly do some more initialization that required the base to have
    // been previously initialized
    // ...

	return nil
}
```


