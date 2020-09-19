const Waf = require('./wafbase');

const DefaultSettings = {
  Rules: [
    { //Anti excessive header, remote file inclusion, scan tools and botnets rule.
      Dacls: [
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_USER_AGENT | Waf.WAF_MATCH_TYPE.MATCH_ALL_SPECIFIED,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,
          UserAgents:{
            RegexArray:[/(DirBuster|OWASP_DIRBUSTER_PROJECT)/igm],
            MatchArray:[]
          },
          MethodTypes: "GET|POST|PUT|PATCH|DELETE|OPTIONS|COPY|HEAD|LOCK|UNLOCK|LINK|UNLINK|PURGE",
          Description: 'Dirb and Dirbuster directory mapping attack.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_USER_AGENT | Waf.WAF_MATCH_TYPE.MATCH_ALL_SPECIFIED,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,
          UserAgents:{
            RegexArray:[/(ATLAS|APPLEBOT|atSpider\/1\.0|autoemailspider|Atomic_Email_Hunter|ContactBot\/0\.2|ContentSmartz|DataCha0s|DBrowse 1\.4(b|d){0,1}|Demo\sBot\s(DOT|Z)\s16b|DSurf15|eCatch\/3\.0|8484\sBoston\sProject\sv\s1\.0)/igm],
            MatchArray:[]
          },
          MethodTypes: "GET|POST|PUT|PATCH|DELETE|OPTIONS|COPY|HEAD|LOCK|UNLOCK|LINK|UNLINK|PURGE",
          Description: 'Common dangerous Botnets trying to steal information.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_USER_AGENT | Waf.WAF_MATCH_TYPE.MATCH_ALL_SPECIFIED,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,
          UserAgents:{
            RegexArray:[/(?:acunetix|analyzer|AhrefsBot|backdoor|bandit|blackwidow|BOT for JCE|core-project|dts agent|emailmagnet|ex(ploit|tract)|flood|grabber|harvest|httrack|havij|hunter|indy library|inspect|LoadTimeBot|mfibot|Microsoft URL Control|Miami Style|morfeus|nessus|NetLyzer|pmafind|scanner|siphon|spbot|sqlmap|survey|teleport|updown_tester|xovibot|masscan)/igm],
            MatchArray:[]
          },
          MethodTypes: "GET|POST|PUT|PATCH|DELETE|OPTIONS|COPY|HEAD|LOCK|UNLOCK|LINK|UNLINK|PURGE",
          Description: 'Known Botnet or Scan tool.'
        }
      ],
      Filters: [
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes:  Waf.WAF_MATCH_TYPE.MATCH_HEADERS,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          Headers: {
            NameArray: [],
            RegexArray: [/^.{1024}/igm],
            MatchArray: []
          },

          Description: 'Excessive header length, possible Header DoS attack.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes:  Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray: [],
            MatchArray: [],
            RegexArray: [/(INCLUDE|REQUIRE)(?:_ONCE){0,1}/igm]
          },

          ParamStrings:{
            MatchArray: [],
            RegexArray: [/(INCLUDE|REQUIRE)(?:_ONCE){0,1}/igm]
          },

          Description: 'Possible Remote File Inclusion attack.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes:  Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray: [],
            MatchArray: [],
            RegexArray: [/^(?:ftp):\/\/[^\/]+\/.+/i]
          },

          ParamStrings:{
            MatchArray: [],
            RegexArray: [/^(?:ftp):\/\/[^\/]+\/.+/i]
          },

          Description: 'Possible Remote File Inclusion attack by remote FTP host.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes:  Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray: [],
            MatchArray: [],
            RegexArray: [/(?:\\x[a-f0-9]{2,4}){25}/igm]
          },

          ParamStrings:{
            MatchArray: [],
            RegexArray: [/(?:\\x[a-f0-9]{2,4}){25}/igm]
          },

          Description: 'Excessive hexadecimal field.'
        }
      ]
    },
    { //Anti path traversal and data exposure rule.
      Dacls: [],
      Filters: [
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes:  Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/(\.\.(\/|\\)|\.\.%(2F|5C))+/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/(\.\.(\/|\\)|\.\.%(2F|5C))+/igm],
            MatchArray:[]
          },

          Description: 'Path traversal attack.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes:  Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING | Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/HTTP_RAW_POST_DATA|HTTP_(?:POS|GE)T_VARS/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/HTTP_RAW_POST_DATA|HTTP_(?:POS|GE)T_VARS/igm],
            MatchArray:[]
          },

          Payloads:{
            MatchArray:[],
            RegexArray:[/HTTP_RAW_POST_DATA|HTTP_(?:POS|GE)T_VARS/igm]
          },

          Description: 'Data exposure exploitation attempt.'
        }
      ]
    },
    { //Anti data exposure and XSS US-ASCII based rule.
      Dacls: [],
      Filters: [
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/phpinfo.php/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/phpinfo.php/igm],
            MatchArray:[]
          },

          Description: 'Data exposure exploitation attempt.'
        },
        {
          //https://github.com/SpiderLabs/owasp-modsecurity-crs/issues/1645
          //https://owasp.org/www-community/xss-filter-evasion-cheatsheet

          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING | Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD | Waf.WAF_MATCH_TYPE.MATCH_HEADERS,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/\xBC\/script\xBE/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/\xBC\/script\xBE/igm],
            MatchArray:[]
          },

          Payloads:{
            RegexArray:[/\xBC\/script\xBE/igm],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/\xBC\/script\xBE/igm],
            MatchArray:[]
          },

          Description: 'XSS attack by 0xbc, 0xbe unescaped char.'
        }
      ]
    },
    { //Anti XSS and SSI command execution attacks rule.
      Dacls: [],
      Filters: [
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING | Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/(\'|\"){0,1}(JAVA|VB)SCRIPT:.(\'|\"){0,1}/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/(\'|\"){0,1}(JAVA|VB)SCRIPT:.(\'|\"){0,1}/igm],
            MatchArray:[]
          },

          Payloads:{
            RegexArray:[/(\'|\"){0,1}(JAVA|VB)SCRIPT:.(\'|\"){0,1}/igm],
            MatchArray:[]
          },

          Description: 'XSS attack by invoke prefix method in request.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING | Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/(EVAL|ALERT|CONFIRM)+(\()+(\'|\")+.*?(\'|\")+(\))+\;?/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/(EVAL|ALERT|CONFIRM)+(\()+(\'|\")+.*?(\'|\")+(\))+\;?/igm],
            MatchArray:[]
          },

          Payloads:{
            RegexArray:[/(EVAL|ALERT|CONFIRM)+(\()+(\'|\")+.*?(\'|\")+(\))+\;?/igm],
            MatchArray:[]
          },

          Description: 'XSS attack by eval or local function call.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING | Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/<!--#(?:CONFIG|ECHO|EXEC|FLASTMOD|FSIZE|INCLUDE)\b.+?-->/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/<!--#(?:CONFIG|ECHO|EXEC|FLASTMOD|FSIZE|INCLUDE)\b.+?-->/igm],
            MatchArray:[]
          },

          Payloads:{
            RegexArray:[/<!--#(?:CONFIG|ECHO|EXEC|FLASTMOD|FSIZE|INCLUDE)\b.+?-->/igm],
            MatchArray:[]
          },

          Description: 'SSI Command injection attack.'
        }
      ]
    },
    { //Anti mail injection and remote code execution (RCE) rule.
      Dacls: [],
      Filters: [
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING | Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/\x0A\b((Reply-)?To|B?Cc|Content-(Td|Type)\w?)\b\s*:.*?\@.+/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/\x0A\b((Reply-)?To|B?Cc|Content-(Td|Type)\w?)\b\s*:.*?\@.+/igm],
            MatchArray:[]
          },

          Payloads:{
            RegexArray:[/\x0A\b((Reply-)?To|B?Cc|Content-(Td|Type)\w?)\b\s*:.*?\@.+/igm],
            MatchArray:[]
          },

          Description: 'Mail header injection attack.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING | Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/(?:<\?[\s\S]+)|#!\/(?:USR|BIN)\/.+?\s/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/(?:<\?[\s\S]+)|#!\/(?:USR|BIN)\/.+?\s/igm],
            MatchArray:[]
          },

          Payloads:{
            RegexArray:[/(?:<\?[\s\S]+)|#!\/(?:USR|BIN)\/.+?\s/igm],
            MatchArray:[]
          },

          Description: 'Remote shellcode execution attack.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING | Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD | Waf.WAF_MATCH_TYPE.MATCH_COOKIES,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/\b(?:eval)\s*\(\s*(?:base64_decode|exec|file_get_contents|gzinflate|passthru|shell_exec|stripslashes|system)\s*\((\)?\)?);?/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/\b(?:eval)\s*\(\s*(?:base64_decode|exec|file_get_contents|gzinflate|passthru|shell_exec|stripslashes|system)\s*\((\)?\)?);?/igm],
            MatchArray:[]
          },

          Payloads:{
            RegexArray:[/\b(?:eval)\s*\(\s*(?:base64_decode|exec|file_get_contents|gzinflate|passthru|shell_exec|stripslashes|system)\s*\((\)?\)?);?/igm],
            MatchArray:[]
          },

          Cookies:{
            NameArray:[],
            RegexArray:[/\b(?:eval)\s*\(\s*(?:base64_decode|exec|file_get_contents|gzinflate|passthru|shell_exec|stripslashes|system)\s*\((\)?\)?);?/igm],
            MatchArray:[]
          },

          Description: 'Remote code execution using PHP payload.'
        }
      ]
    },
    { //Anti XSS rule.
      Dacls: [],
      Filters: [
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING | Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD | Waf.WAF_MATCH_TYPE.MATCH_HEADERS,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/\<\s*(SCRIPT|A|B|DIV|BUTTON|IFRAME)[^\>]*\>(.*?)\<\s*\/\s*(SCRIPT|A|B|DIV|BUTTON|IFRAME)\>/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/\<\s*(SCRIPT|A|B|DIV|BUTTON|IFRAME)[^\>]*\>(.*?)\<\s*\/\s*(SCRIPT|A|B|DIV|BUTTON|IFRAME)\>/igm],
            MatchArray:[]
          },

          Payloads:{
            RegexArray:[/\<\s*(SCRIPT|A|B|DIV|BUTTON|IFRAME)[^\>]*\>(.*?)\<\s*\/\s*(SCRIPT|A|B|DIV|BUTTON|IFRAME)\>/igm],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/\<\s*(SCRIPT|A|B|DIV|BUTTON|IFRAME)[^\>]*\>(.*?)\<\s*\/\s*(SCRIPT|A|B|DIV|BUTTON|IFRAME)\>/igm],
            MatchArray:[]
          },

          Description: 'XSS attack using HTML common tags.'
        }
      ]
    },
    { //PHP Vuln. CVE-2012-1823 and Unrestricted File Upload rule.
      Dacls: [],
      Filters: [
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD | Waf.WAF_MATCH_TYPE.MATCH_HEADERS,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          Payloads:{
            RegexArray:[/^-[bcndfiswzT].{20}/igm],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/^-[bcndfiswzT].{20}/igm],
            MatchArray:[]
          },

          Description: 'PHP Vulnerability CVE-2012-1823.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_FILE_EXT,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          FileExtensions:{
            ExtensionsArray:[/\x70\x68(\x70(3|4|5|S|)|\x74\x6d\x6c)/igm],
            RegexArray:[],
            MatchArray:[]
          },

          Description: 'PHP Unrestricted File Upload attack.'
        }
      ]
    },
    { //Anti ASP(X) Unrestricted File Upload rule.
      Dacls: [],
      Filters: [
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_FILE_EXT,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          FileExtensions:{
            ExtensionsArray:[/asp(x)?(::)?\$?(Index_Allocation|Data)?/igm],
            RegexArray:[],
            MatchArray:[]
          },

          Description: 'ASP(X) Unrestricted File Upload attack.'
        }
      ]
    },
    { //Anti SQL Injection rule
      Dacls: [],
      Filters: [
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_HEADERS | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/^.{0,100}\sSLEEP\s\d+/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/^.{0,100}\sSLEEP\s\d+/igm],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/^.{0,100}\sSLEEP\s\d+/igm],
            MatchArray:[]
          },

          Description: 'SQL Injection Time-Based.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_HEADERS | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/^'/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/^'/igm],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/^'/igm],
            MatchArray:[]
          },

          Description: 'SQL Injection using unescaped single-quote.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_HEADERS | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/^.{0,128}\bAND\s+EXTRACTVALUE\s\w/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/^.{0,128}\bAND\s+EXTRACTVALUE\s\w/igm],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/^.{0,128}\bAND\s+EXTRACTVALUE\s\w/igm],
            MatchArray:[]
          },

          Description: 'Blind SQL Injection'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_HEADERS | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/^(\'\s){0,1}(OR|AND)(\s{0,1}|\s{0,1}\')\w(\'\s{0,1}|\'){0,1}=(\s{0,1}|\s{0,1}\'|\'){0,1}\w(\'\s{0,1}|\'){0,1}/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/^(\'\s){0,1}(OR|AND)(\s{0,1}|\s{0,1}\')\w(\'\s{0,1}|\'){0,1}=(\s{0,1}|\s{0,1}\'|\'){0,1}\w(\'\s{0,1}|\'){0,1}/igm],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/^(\'\s){0,1}(OR|AND)(\s{0,1}|\s{0,1}\')\w(\'\s{0,1}|\'){0,1}=(\s{0,1}|\s{0,1}\'|\'){0,1}\w(\'\s{0,1}|\'){0,1}/igm],
            MatchArray:[]
          },

          Description: 'Tautology assertion SQL Injection.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_HEADERS | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/(?:\b|\d)INSERT\b.+?(?:\b|\d)INTO\b.{1,150}(?:\b|\d)VALUES\b.*?\(.+?\)/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/(?:\b|\d)INSERT\b.+?(?:\b|\d)INTO\b.{1,150}(?:\b|\d)VALUES\b.*?\(.+?\)/igm],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/(?:\b|\d)INSERT\b.+?(?:\b|\d)INTO\b.{1,150}(?:\b|\d)VALUES\b.*?\(.+?\)/igm],
            MatchArray:[]
          },

          Description: 'SQL Injection by Insert method.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_HEADERS | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/^(?:ADMIN(?:ISTRATOR)?)['\"].*?(?:--|#|\/\\*)/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/^(?:ADMIN(?:ISTRATOR)?)['\"].*?(?:--|#|\/\\*)/igm],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/^(?:ADMIN(?:ISTRATOR)?)['\"].*?(?:--|#|\/\\*)/igm],
            MatchArray:[]
          },

          Description: 'Admin comment based SQL Injection.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_HEADERS | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/^.{0,128}\bUNION\s+SELECT\b.{1,128}(FROM|WHERE)\b/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/^.{0,128}\bUNION\s+SELECT\b.{1,128}(FROM|WHERE)\b/igm],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/^.{0,128}\bUNION\s+SELECT\b.{1,128}(FROM|WHERE)\b/igm],
            MatchArray:[]
          },

          Description: 'SQL Injection by UNION method.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_HEADERS | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/^(?:\b|\d)+\s(?:CEIL|CONCAT|CONV|FLOOR|VERSION)\b/ig],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/^(?:\b|\d)+\s(?:CEIL|CONCAT|CONV|FLOOR|VERSION)\b/ig],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/^(?:\b|\d)+\s(?:CEIL|CONCAT|CONV|FLOOR|VERSION)\b/ig],
            MatchArray:[]
          },

          Description: 'SQL Injection by common functions. #1'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_HEADERS | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/(?:\b(?:null|and|or)\b|\|\||&&)\s*.{0,50}\bselect\b./im],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/(?:\b(?:null|and|or)\b|\|\||&&)\s*.{0,50}\bselect\b./im],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/(?:\b(?:null|and|or)\b|\|\||&&)\s*.{0,50}\bselect\b./im],
            MatchArray:[]
          },

          Description: 'Suspicious NULL assertion injection in SQL Injection attack.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_HEADERS | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/^(?:\b(?:null|and|or)\b|\|\||&&)?\s*union\s+(?:all\s+)?select\b/i],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/^(?:\b(?:null|and|or)\b|\|\||&&)?\s*union\s+(?:all\s+)?select\b/i],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/^(?:\b(?:null|and|or)\b|\|\||&&)?\s*union\s+(?:all\s+)?select\b/i],
            MatchArray:[]
          },

          Description: 'Suspicious NULL assertion based SQL injection.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_HEADERS | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/^-?\d+.{0,32}(?:\bAND\b.{0,64})?\b(?:UNION|SELECT)\b/im],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/^-?\d+.{0,32}(?:\bAND\b.{0,64})?\b(?:UNION|SELECT)\b/im],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/^-?\d+.{0,32}(?:\bAND\b.{0,64})?\b(?:UNION|SELECT)\b/im],
            MatchArray:[]
          },

          Description: 'Negative number based SQL Injection.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_HEADERS | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/.{2,}\bORDER\sBY\s*(\d*|\w*)?/im],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/.{2,}\bORDER\sBY\s*(\d*|\w*)?/im],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/.{2,}\bORDER\sBY\s*(\d*|\w*)?/im],
            MatchArray:[]
          },

          Description: 'Order by column based SQL Injection.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_HEADERS | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/.{2,}\b(UNION|INTERSECT|EXCEPT)\s*SELECT\s*(NULL[,\s]*)+(?:--)/im],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/.{2,}\b(UNION|INTERSECT|EXCEPT)\s*SELECT\s*(NULL[,\s]*)+(?:--)/im],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/.{2,}\b(UNION|INTERSECT|EXCEPT)\s*SELECT\s*(NULL[,\s]*)+(?:--)/im],
            MatchArray:[]
          },

          Description: 'Union, intersect or except based method to SQL Injection.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_HEADERS | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/^(\'|\s){0,}(OR|AND)(\s{0,1}|\s{0,1}\')\w(\'\s{0,1}|\'){0,1}=(\s{0,1}|\s{0,1}\'|\'){0,1}\w(\'\s{0,1}|\'){0,1}/im],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/^(\'|\s){0,}(OR|AND)(\s{0,1}|\s{0,1}\')\w(\'\s{0,1}|\'){0,1}=(\s{0,1}|\s{0,1}\'|\'){0,1}\w(\'\s{0,1}|\'){0,1}/im],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/^(\'|\s){0,}(OR|AND)(\s{0,1}|\s{0,1}\')\w(\'\s{0,1}|\'){0,1}=(\s{0,1}|\s{0,1}\'|\'){0,1}\w(\'\s{0,1}|\'){0,1}/im],
            MatchArray:[]
          },

          Description: 'Improved tautology assertion based SQL Injection.'
        }
      ]
    },
    { //Anti Null byte rule
      Dacls: [],
      Filters: [
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_HEADERS | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/\x00/gm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/\x00/gm],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/\x00/gm],
            MatchArray:[]
          },

          Description: 'ASCII character 0x00 (NULL BYTE) injection attack.'
        }
      ]
    },
    { //Anti XSS rule
      Dacls: [],
      Filters: [
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_HEADERS | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING | Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/\bFunction\s*[({](.|\s)*?[})]\s*\(.*?\)|\bfunction\s*\(.*?\)\s*{(.|\s)*?}|(?:\[|new)\s*class\s*extends\b|\bArray\s*.*\s*from\b/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/\bFunction\s*[({](.|\s)*?[})]\s*\(.*?\)|\bfunction\s*\(.*?\)\s*{(.|\s)*?}|(?:\[|new)\s*class\s*extends\b|\bArray\s*.*\s*from\b/igm],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/\bFunction\s*[({](.|\s)*?[})]\s*\(.*?\)|\bfunction\s*\(.*?\)\s*{(.|\s)*?}|(?:\[|new)\s*class\s*extends\b|\bArray\s*.*\s*from\b/igm],
            MatchArray:[]
          },

          Payloads:{
            RegexArray:[/\bFunction\s*[({](.|\s)*?[})]\s*\(.*?\)|\bfunction\s*\(.*?\)\s*{(.|\s)*?}|(?:\[|new)\s*class\s*extends\b|\bArray\s*.*\s*from\b/igm],
            MatchArray:[]
          },

          Description: 'XSS attack by function, class or array injection.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_HEADERS | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING | Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/\b(?:document|window|this)\s*\[.+?\]\s*[\[(]/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/\b(?:document|window|this)\s*\[.+?\]\s*[\[(]/igm],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/\b(?:document|window|this)\s*\[.+?\]\s*[\[(]/igm],
            MatchArray:[]
          },

          Payloads:{
            RegexArray:[/\b(?:document|window|this)\s*\[.+?\]\s*[\[(]/igm],
            MatchArray:[]
          },

          Description: 'XSS DOM based injection.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_HEADERS | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING | Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/<.+?\bon[a-z]{3,19}\b\s*=.+?>/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/<.+?\bon[a-z]{3,19}\b\s*=.+?>/igm],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/<.+?\bon[a-z]{3,19}\b\s*=.+?>/igm],
            MatchArray:[]
          },

          Payloads:{
            RegexArray:[/<.+?\bon[a-z]{3,19}\b\s*=.+?>/igm],
            MatchArray:[]
          },

          Description: 'XSS DOM based by HTML event attributes.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_HEADERS | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING | Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/\bdocument\s*\.\s*(?:body|cookie|location|open|write(?:ln)?)\s*(\(|\[|\=\s*(\"|\')+)+.*(\)|\]|(\"|\')+)+/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/\bdocument\s*\.\s*(?:body|cookie|location|open|write(?:ln)?)\s*(\(|\[|\=\s*(\"|\')+)+.*(\)|\]|(\"|\')+)+/igm],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/\bdocument\s*\.\s*(?:body|cookie|location|open|write(?:ln)?)\s*(\(|\[|\=\s*(\"|\')+)+.*(\)|\]|(\"|\')+)+/igm],
            MatchArray:[]
          },

          Payloads:{
            RegexArray:[/\bdocument\s*\.\s*(?:body|cookie|location|open|write(?:ln)?)\s*(\(|\[|\=\s*(\"|\')+)+.*(\)|\]|(\"|\')+)+/igm],
            MatchArray:[]
          },

          Description: 'XSS DOM based injection.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_HEADERS | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING | Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/<.+?\b(?:href|(?:form)?action|background|code|data|location|name|poster|src|value)\s*=\s*['\"]?(?:(?:f|ht)tps?:)?\/\/\w+\.\w*/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/<.+?\b(?:href|(?:form)?action|background|code|data|location|name|poster|src|value)\s*=\s*['\"]?(?:(?:f|ht)tps?:)?\/\/\w+\.\w*/igm],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/<.+?\b(?:href|(?:form)?action|background|code|data|location|name|poster|src|value)\s*=\s*['\"]?(?:(?:f|ht)tps?:)?\/\/\w+\.\w*/igm],
            MatchArray:[]
          },

          Payloads:{
            RegexArray:[/<.+?\b(?:href|(?:form)?action|background|code|data|location|name|poster|src|value)\s*=\s*['\"]?(?:(?:f|ht)tps?:)?\/\/\w+\.\w*/igm],
            MatchArray:[]
          },

          Description: 'XSS DOM poisoning based by common attributes.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_HEADERS | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING | Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/\W(?:background(-image)?|-moz-binding)\s*:[^}]*?\burl\s*\([^)]+?(https?:)?\/\/\w/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/\W(?:background(-image)?|-moz-binding)\s*:[^}]*?\burl\s*\([^)]+?(https?:)?\/\/\w/igm],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/\W(?:background(-image)?|-moz-binding)\s*:[^}]*?\burl\s*\([^)]+?(https?:)?\/\/\w/igm],
            MatchArray:[]
          },

          Payloads:{
            RegexArray:[/\W(?:background(-image)?|-moz-binding)\s*:[^}]*?\burl\s*\([^)]+?(https?:)?\/\/\w/igm],
            MatchArray:[]
          },

          Description: 'XSS possible deface attack by embedded (S)CSS attributes.'
        },
      ]
    },
    { //Anti SQL injection rule.
      Dacls: [
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_USER_AGENT,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,
          UserAgents:{
            RegexArray:[/^(\uff07|\d\s*\uff07)/gm],
            MatchArray:[]
          },
          Description: 'SQL Injection single quote UTF-16 beginning string.'
        }
      ],
      Filters: [
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/^(\uff07|\d\s*\uff07)/gm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/^(\uff07|\d\s*\uff07)/gm],
            MatchArray:[]
          },

          Payloads:{
            RegexArray:[/^(\uff07|\d\s*\uff07)/gm],
            MatchArray:[]
          },

          Description: 'SQL Injection single quote UTF-16 beginning string.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/^(\d*|\w*)\s*(\'|\uff07)?\s*\)\s*(OR|AND)/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/^(\d*|\w*)\s*(\'|\uff07)?\s*\)\s*(OR|AND)/igm],
            MatchArray:[]
          },

          Payloads:{
            RegexArray:[/^(\d*|\w*)\s*(\'|\uff07)?\s*\)\s*(OR|AND)/igm],
            MatchArray:[]
          },

          Description: 'SQL Injection boolean blind based #1.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/^(\d*|\w*)\s*(\'|\uff07)?\s*\)\s*(ORDER\s*BY|UNION\s*ALL\s*)/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/^(\d*|\w*)\s*(\'|\uff07)?\s*\)\s*(ORDER\s*BY|UNION\s*ALL\s*)/igm],
            MatchArray:[]
          },

          Payloads:{
            RegexArray:[/^(\d*|\w*)\s*(\'|\uff07)?\s*\)\s*(ORDER\s*BY|UNION\s*ALL\s*)/igm],
            MatchArray:[]
          },

          Description: 'SQL Injection "UNION" or "ORDER BY" based #1.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/^(\d*|\w*)\s*(\'|\uff07)?\s*\)*\s*(ORDER\s*BY|UNION\s*ALL)\s*(SELECT|ORDER\s*BY)*/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/^(\d*|\w*)\s*(\'|\uff07)?\s*\)*\s*(ORDER\s*BY|UNION\s*ALL)\s*(SELECT|ORDER\s*BY)*/igm],
            MatchArray:[]
          },

          Payloads:{
            RegexArray:[/^(\d*|\w*)\s*(\'|\uff07)?\s*\)*\s*(ORDER\s*BY|UNION\s*ALL)\s*(SELECT|ORDER\s*BY)*/igm],
            MatchArray:[]
          },

          Description: 'SQL Injection "UNION" or "ORDER BY" based #2.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/^(\d*|\w*)\s*(\'|\uff07)?\s*\)*\s*(OR|AND)\s*((SELECT|UNION|DECLARE|BEGIN|INSERT|UPDATE|DELETE|WAITFOR|RLIKE|ORDER\s+BY|\(.+\))|(\'|\uff07)\w+(\'|\uff07)(\=|\!\=)+(\'|\uff07)\w+(\'|\uff07)|-?\d+\s*\=\s*(\(|SELECT|\w+)|\s*\w*\s*IN\s*\()/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/^(\d*|\w*)\s*(\'|\uff07)?\s*\)*\s*(OR|AND)\s*((SELECT|UNION|DECLARE|BEGIN|INSERT|UPDATE|DELETE|WAITFOR|RLIKE|ORDER\s+BY|\(.+\))|(\'|\uff07)\w+(\'|\uff07)(\=|\!\=)+(\'|\uff07)\w+(\'|\uff07)|-?\d+\s*\=\s*(\(|SELECT|\w+)|\s*\w*\s*IN\s*\()/igm],
            MatchArray:[]
          },

          Payloads:{
            RegexArray:[/^(\d*|\w*)\s*(\'|\uff07)?\s*\)*\s*(OR|AND)\s*((SELECT|UNION|DECLARE|BEGIN|INSERT|UPDATE|DELETE|WAITFOR|RLIKE|ORDER\s+BY|\(.+\))|(\'|\uff07)\w+(\'|\uff07)(\=|\!\=)+(\'|\uff07)\w+(\'|\uff07)|-?\d+\s*\=\s*(\(|SELECT|\w+)|\s*\w*\s*IN\s*\()/igm],
            MatchArray:[]
          },

          Description: 'SQL Injection boolean blind based #2.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/^(\d*|\w*)\s*(\'|\uff07|\")?\s*\)*\s*(RLIKE|WAITFOR)\s*\w*/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/^(\d*|\w*)\s*(\'|\uff07|\")?\s*\)*\s*(RLIKE|WAITFOR)\s*\w*/igm],
            MatchArray:[]
          },

          Payloads:{
            RegexArray:[/^(\d*|\w*)\s*(\'|\uff07|\")?\s*\)*\s*(RLIKE|WAITFOR)\s*\w*/igm],
            MatchArray:[]
          },

          Description: 'SQL Injection using "RLIKE" or "WAITFOR" command.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/^(\d*|\w*)\s*(\'|\uff07|\")?\s*\)*\s*;(SELECT|WAITFOR|DECLARE)\s*\w*/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/^(\d*|\w*)\s*(\'|\uff07|\")?\s*\)*\s*;(SELECT|WAITFOR|DECLARE)\s*\w*/igm],
            MatchArray:[]
          },

          Payloads:{
            RegexArray:[/^(\d*|\w*)\s*(\'|\uff07|\")?\s*\)*\s*;(SELECT|WAITFOR|DECLARE)\s*\w*/igm],
            MatchArray:[]
          },

          Description: 'SQL Injection using "SELECT", "WAITFOR" or "DECLARE" command.'
        }
      ]
    },
    { //Anti Advanced SQL Injection rule.
      Dacls: [],
      Filters: [
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/^-?(\d*|\w*)\s*(\'|\uff07|\")?\s*(\)){0,3}\s*(ORDER\s*BY|UNION\s*ALL\s*)/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/^-?(\d*|\w*)\s*(\'|\uff07|\")?\s*(\)){0,3}\s*(ORDER\s*BY|UNION\s*ALL\s*)/igm],
            MatchArray:[]
          },

          Payloads:{
            NameArray:[],
            RegexArray:[/^-?(\d*|\w*)\s*(\'|\uff07|\")?\s*(\)){0,3}\s*(ORDER\s*BY|UNION\s*ALL\s*)/igm],
            MatchArray:[]
          },

          Description: 'Advanced SQL injection using "ORDER BY" or "UNION" operators.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/^-?(\d+|\w+)\s*(\'|\uff07|\")?\s*(\)){0,3}\s*\b(AND|OR)\s*(SELECT|UNION|DECLARE|BEGIN|INSERT|UPDATE|DELETE|WAITFOR|RLIKE|ORDER\s+BY|\(.+\))/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/^-?(\d+|\w+)\s*(\'|\uff07|\")?\s*(\)){0,3}\s*\b(AND|OR)\s*(SELECT|UNION|DECLARE|BEGIN|INSERT|UPDATE|DELETE|WAITFOR|RLIKE|ORDER\s+BY|\(.+\))/igm],
            MatchArray:[]
          },

          Payloads:{
            NameArray:[],
            RegexArray:[/^-?(\d+|\w+)\s*(\'|\uff07|\")?\s*(\)){0,3}\s*\b(AND|OR)\s*(SELECT|UNION|DECLARE|BEGIN|INSERT|UPDATE|DELETE|WAITFOR|RLIKE|ORDER\s+BY|\(.+\))/igm],
            MatchArray:[]
          },

          Description: 'Advanced SQL injection boolean blind based.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/^-?(\d*|\w*)\s*(\'|\uff07|\")?\s*(\)){0,3};\s*(SELECT|DECLARE|WAITFOR|CREATE|\()\s*/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/^-?(\d*|\w*)\s*(\'|\uff07|\")?\s*(\)){0,3};\s*(SELECT|DECLARE|WAITFOR|CREATE|\()\s*/igm],
            MatchArray:[]
          },

          Payloads:{
            NameArray:[],
            RegexArray:[/^-?(\d*|\w*)\s*(\'|\uff07|\")?\s*(\)){0,3};\s*(SELECT|DECLARE|WAITFOR|CREATE|\()\s*/igm],
            MatchArray:[]
          },

          Description: 'Advanced SQL injection using "SELECT", "DECLARE", "WAITFOR" or "CREATE" methods.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/^-?\w*(\'|\"|\uff07)*\s*[\(\)]{1,3}\s*(AND|SELECT|WHERE|AS|;)/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/^-?\w*(\'|\"|\uff07)*\s*[\(\)]{1,3}\s*(AND|SELECT|WHERE|AS|;)/igm],
            MatchArray:[]
          },

          Payloads:{
            NameArray:[],
            RegexArray:[/^-?\w*(\'|\"|\uff07)*\s*[\(\)]{1,3}\s*(AND|SELECT|WHERE|AS|;)/igm],
            MatchArray:[]
          },

          Description: 'Advanced SQL injection using very dangerous SQLMAP Payloads LEVEL 4.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/^\w+\`\=\`.+\`\s*(AND|OR|\w+|\;)/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/^\w+\`\=\`.+\`\s*(AND|OR|\w+|\;)/igm],
            MatchArray:[]
          },

          Payloads:{
            NameArray:[],
            RegexArray:[/^\w+\`\=\`.+\`\s*(AND|OR|\w+|\;)/igm],
            MatchArray:[]
          },

          Description: 'Advanced SQL injection boolean blind based #3.'
        }
      ]
    },
    { //Anti payload obfuscation and PHP Remote Code Execution (RCE) rule.
      Dacls: [],
      Filters: [
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_HEADERS | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING | Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/^(%u(\w{2}|\w{4})){16}/gm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/^(%u(\w{2}|\w{4})){16}/gm],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/^(%u(\w{2}|\w{4})){16}/gm],
            MatchArray:[]
          },

          Payloads:{
            RegexArray:[/^(%u(\w{2}|\w{4})){16}/gm],
            MatchArray:[]
          },

          Description: 'Possible UTF-8/16 encoded and obfuscated payload injection.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_HEADERS | Waf.WAF_MATCH_TYPE.MATCH_PARAM_STRING | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING | Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          QueryStrings:{
            NameArray:[],
            RegexArray:[/\b(XDEBUG_SESSION_START|invokefunction|call_user_func_array)\b/igm],
            MatchArray:[]
          },

          ParamStrings:{
            NameArray:[],
            RegexArray:[/\b(XDEBUG_SESSION_START|invokefunction|call_user_func_array)\b/igm],
            MatchArray:[]
          },

          Headers:{
            NameArray:[],
            RegexArray:[/\b(XDEBUG_SESSION_START|invokefunction|call_user_func_array)\b/igm],
            MatchArray:[]
          },

          Payloads:{
            RegexArray:[/\b(XDEBUG_SESSION_START|invokefunction|call_user_func_array)\b/igm],
            MatchArray:[]
          },

          Description: 'Remote code execution (RCE) attack attempt.'
        }
      ]
    },
    { //Anti prototype pollution rule.
      Dacls: [],
      Filters: [
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_HEADERS | Waf.WAF_MATCH_TYPE.MATCH_PAYLOAD | Waf.WAF_MATCH_TYPE.MATCH_ALL_SPECIFIED,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          Headers:{
            NameArray:[],
            RegexArray:[/^application\/json/igm],
            MatchArray:[]
          },

          Payloads:{
            RegexArray:[/(?:(?:{|%7B|%u007B|\[|%5B|%u005B)(?:.|\s)*(?:"|%22|%u0022)(?:__proto__|toString|toLocaleString|isPrototypeOf|hasOwnProperty|propertyIsEnumerable|valueOf|__defineGetter__|__defineSetter__|__lookupGetter__|constructor)(?:"|%22|%u0022)(?:.|\s)*(?:}|%7D|%u007D|\]|%5D|%u005D))/igm],
            MatchArray:[]
          },

          Description: 'Possible Prototype Pollution and Remote Code Execution #1.'
        },
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_COOKIES | Waf.WAF_MATCH_TYPE.MATCH_QUERY_STRING,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          Cookies:{
            NameArray:[],
            RegexArray:[/(?:(?:{|%7B|%u007B|\[|%5B|%u005B)(?:.|\s)*(?:"|%22|%u0022)(?:__proto__|toString|toLocaleString|isPrototypeOf|hasOwnProperty|propertyIsEnumerable|valueOf|__defineGetter__|__defineSetter__|__lookupGetter__|constructor)(?:"|%22|%u0022)(?:.|\s)*(?:}|%7D|%u007D|\]|%5D|%u005D))/igm],
            MatchArray:[]
          },

          QueryStrings:{
            NameArray:[],
            RegexArray:[/(?:(?:{|%7B|%u007B|\[|%5B|%u005B)(?:.|\s)*(?:"|%22|%u0022)(?:__proto__|toString|toLocaleString|isPrototypeOf|hasOwnProperty|propertyIsEnumerable|valueOf|__defineGetter__|__defineSetter__|__lookupGetter__|constructor)(?:"|%22|%u0022)(?:.|\s)*(?:}|%7D|%u007D|\]|%5D|%u005D))/igm],
            MatchArray:[]
          },

          Description: 'Possible Prototype Pollution and Remote Code Execution #2.'
        }
      ]
    },
    { // DoS rule.
      Dacls: [],
      Filters: [
        {
          NetworkLayers: Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 | Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
          MatchTypes:  Waf.WAF_MATCH_TYPE.MATCH_ATTEMPTS,
          ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
          Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

          Attempts: {
            MaxAttempts: 1024,
            RenewAttemptsInterval: 600
          },

          Description: 'Possible Denial of Service attack.'
        }
      ]
    }
  ],
  Callbacks: [],
  AccessTable: []
}

module.exports = {

  DefaultSettings: DefaultSettings

}