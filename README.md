# Mini WAF

<p align="center">
<img src="https://user-images.githubusercontent.com/32225687/78806753-849c1480-7999-11ea-8ad5-4f15ce5ad5fa.png" data-canonical-src="https://user-images.githubusercontent.com/32225687/78806753-849c1480-7999-11ea-8ad5-4f15ce5ad5fa.png" width="192" height="192"/>
</p>

## Getting started into Mini-WAF!
<p align="justify">A Minimalistic Web Application Firewall for your purposes in NodeJS servers. It will protect your servers against XSS, XSRF, DOS, LFI, SQL Injection, Unauthorized Remote Access, Unhandled Exceptions and Botnets attacks. Mini-WAF is a Minimalistic Web Application Firewall that avoid and block several attacks in HTTP and HTTPS protocols with a great support to IPv4 and IPv6.</p>

## Installation

<p align="center">
<img src="https://nodei.co/npm/mini-waf.png?downloads=true&downloadRank=true&stars=true"/>
</p>
<p align="justify">You must run the following terminal command in same path of your project.<p>
  
```
npm install mini-waf --save
```

## First use of Mini-WAF with Express
<p align="justify">After install Mini-WAF and it's dependencies you need load our middleware with an initialized object that contains all rules, callbacks and properties necessary to protect your application. By default, you can load our own waf config in wafrules module.</p>

```javascript

const express = require("express");
const app = express();

const Waf = require('mini-waf/wafbase');
const wafrules = require('mini-waf/wafrules');

//Register the middleware of Mini-WAF with standard rules.
app.use(Waf.WafMiddleware(wafrules.DefaultSettings));

//Create your routes in your way!
app.use((req, res) => {
  //Do your work in anywhere.
  res.send('Some data...');
  res.end();
});

app.listen(55100, function () {
  console.log("Running server on port 55100!");
});

```

## Mini-WAF blocking Denial of Service attacks
<p align="justify">With custom rules we can block specified methods for specific IPs or User-Agents, and also for specific routes just creating a simple DACL object and adding it to our rule.</p>

```javascript
Dacls: [
  {
    NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4,
    MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_METHOD_TYPE,
    ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
    Directions: Waf.WAF_RULE_DIRECTION.INBOUND,
    MethodTypes: "GET|POST|PUT|DELETE|PATCH",
    Description: 'Blocking GET, POST, PUT, DELETE, PATCH request methods.'
  }
]
```

<p align="justify">Also, block unauthorized access is very easy.</p>

```javascript
Dacls: [
  {
    NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4,
    MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_IP,
    ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
    Directions: Waf.WAF_RULE_DIRECTION.INBOUND,
    Ipv4Address: '206.189.180.4',
    Description: 'Blocking a specific IP address.'
  }
]
```
## Log of attacks

<p align="center">
<img src="https://user-images.githubusercontent.com/32225687/78816633-625dc300-79a8-11ea-88f2-76f4409a218f.png" data-canonical-src="https://user-images.githubusercontent.com/32225687/78816633-625dc300-79a8-11ea-88f2-76f4409a218f.png"/>
</p>

<p align="center">
<img src="https://user-images.githubusercontent.com/32225687/78817247-49094680-79a9-11ea-865c-a45ca8867bc2.png" data-canonical-src="https://user-images.githubusercontent.com/32225687/78817247-49094680-79a9-11ea-865c-a45ca8867bc2.png"/>
</p>
