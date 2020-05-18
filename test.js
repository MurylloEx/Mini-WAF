const express = require('express');
const Waf = require('./wafbase');
const Rules = require('./wafrules');
const http = require('http');

const app = express();

app.use(Waf.WafMiddleware(Rules.DefaultSettings));

app.get('/', function(req, res){
    res.end('Hello from Mini-WAF unit test.');
});

app.listen(55100);

http.get('http://localhost:55100/', (res)=>{
    process.exit(0);
});