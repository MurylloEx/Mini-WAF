const Ip = require('ip');
const fs = require('fs');
const path = require('path');
const os = require('os');
const colors = require('colors');

const PROTOCOL_IPV4 = 0x01;
const	PROTOCOL_IPV6 = 0x02;

function CheckFlags(value, flag){
  return ((value & flag) === flag);
}

function CookieParse(str, options) {
  if (typeof str !== 'string') {
    return {};
  }

  var obj = {}
  var opt = options || {};
  var pairs = str.split(/; */);
  var dec = opt.decode || decodeURIComponent;

  for (var i = 0; i < pairs.length; i++) {
    var pair = pairs[i];
    var eq_idx = pair.indexOf('=');

    if (eq_idx < 0) {
      continue;
    }

    var key = pair.substr(0, eq_idx).trim()
    var val = pair.substr(++eq_idx, pair.length).trim();

    if ('"' == val[0]) {
      val = val.slice(1, -1);
    }

    if (undefined == obj[key]) {
      obj[key] = (function (str, decode) {
        try {
          return decodeURIComponent(str);
        } catch (e) {
          return str;
        }
      })(val, dec);
    }
  }

  return obj;
}

function EnumAvailableFiles(req, enumProc) {
  if (req.files) {
    let breakEnum = false;
    for (let fieldname in req.files) {
      if (!breakEnum) {
        if (req.files[fieldname].length) {
          for (let idx = 0; idx < req.files[fieldname].length; idx++) {
            let finfo = req.files[fieldname][idx];
            let fname = finfo.name || finfo.filename || finfo.originalname;
            enumProc(finfo, fname, () => {
              breakEnum = true;
              idx = req.files[fieldname].length;
            });
          }
        }
        else {
          let finfo = req.files[fieldname];
          let fname = finfo.name || finfo.filename || finfo.originalname;
          enumProc(finfo, fname, () => {
            breakEnum = true;
          });
        }
      }
      else {
        break;
      }
    }
  }
}

function AddEntryInAccessTable(ptrWafObj, ptrFlt, targIp, networkLayer) {
  let uptimestamp = new Date().getTime();
  let downtimestamp = (uptimestamp - (ptrFlt.Attempts.RenewAttemptsInterval * 0x3e8));
  let accessList = [];
  let tableResult = {};
  let oldAccess = [];
  let inc_len = 0;
  let exceeded = true;
  switch (networkLayer) {
    case PROTOCOL_IPV4:
      accessList = ptrWafObj.AccessTable.filter(function (ptrAccessEntry, idx, ptrAccessTable) {
        if (((ptrAccessEntry.Timestamp < downtimestamp) || (ptrAccessEntry.Timestamp > uptimestamp)) && Ip.isEqual(ptrAccessEntry.Ipv4Address, targIp)) {
          oldAccess.push(ptrAccessTable[idx]);
        }
        return (((ptrAccessEntry.Timestamp >= downtimestamp) && (ptrAccessEntry.Timestamp <= uptimestamp)) && Ip.isEqual(ptrAccessEntry.Ipv4Address, targIp));
      });
      for (let r_idx = 0; r_idx < oldAccess.length; r_idx++) {
        ptrWafObj.AccessTable.splice(ptrWafObj.AccessTable.indexOf(oldAccess[r_idx]), 1);
      }
      if (accessList.length < ptrFlt.Attempts.MaxAttempts) {
        ptrWafObj.AccessTable.push({ Ipv4Address: targIp, Ipv6Address: '', Timestamp: new Date().getTime() });
        exceeded = false;
        inc_len++;
      }
      tableResult = {
        RemainingAttempts: (accessList.length > ptrFlt.Attempts.MaxAttempts ? 0 : (ptrFlt.Attempts.MaxAttempts - (accessList.length + inc_len))),
        CurrentAttempts: accessList.length + inc_len,
        Exceeded: exceeded
      };
      accessList = null;
      return tableResult;
    case PROTOCOL_IPV6:
      accessList = ptrWafObj.AccessTable.filter(function (ptrAccessEntry, idx, ptrAccessTable) {
        if ((ptrAccessEntry.Timestamp < downtimestamp) || (ptrAccessEntry.Timestamp > uptimestamp) && Ip.isEqual(ptrAccessEntry.Ipv6Address, targIp)) {
          oldAccess.push(ptrAccessTable[idx]);
        }
        return (((ptrAccessEntry.Timestamp >= downtimestamp) && (ptrAccessEntry.Timestamp <= uptimestamp)) && Ip.isEqual(ptrAccessEntry.Ipv6Address, targIp));
      });
      for (let r_idx = 0; r_idx < oldAccess.length; r_idx++) {
        ptrWafObj.AccessTable.splice(ptrWafObj.AccessTable.indexOf(oldAccess[r_idx]), 1);
      }
      if (accessList.length < ptrFlt.Attempts.MaxAttempts) {
        ptrWafObj.AccessTable.push({ Ipv4Address: '', Ipv6Address: targIp, Timestamp: new Date().getTime() });
        exceeded = false;
        inc_len++;
      }
      tableResult = {
        RemainingAttempts: (accessList.length > ptrFlt.Attempts.MaxAttempts ? 0 : (ptrFlt.Attempts.MaxAttempts - (accessList.length + inc_len))),
        CurrentAttempts: accessList.length + inc_len,
        Exceeded: exceeded
      };
      accessList = null;
      return tableResult;
    default:
      return false;
  }
}

function DisplayBlockedEvent(event){
  console.log(
    `-> Mini-WAF has protected your server now!`.white.bgRed + os.EOL +
    `   Blocked triggered event by remote IP address: ${event.request.ip} at ${new Date().toLocaleString()}!`.red + os.EOL +
    `   Reason of blocking action: ${event.reason.green}`.yellow + os.EOL +
    `   Method type: ${event.request.method.red}`.yellow + os.EOL +
    `   Port number: ${String(event.request.connection.localPort).red}`.yellow + os.EOL +
    `   Traffic direction: ${String((CheckFlags(event.wafComp.Directions, 0x01) && CheckFlags(event.wafComp.Directions, 0x02) ? 'Inbound | Outbound' : (CheckFlags(event.wafComp.Directions, 0x01) ? 'Inbound' : (CheckFlags(event.wafComp.Directions, 0x02) ? 'Outbound' : 'None')))).red}`.yellow + os.EOL +
    `   Event code: ${('0x' + Number(new Date().getTime() + Math.floor(10 ** 9 * Math.random())).toString(16)).red}\n`.green
  );
}

function DisplayAuditEvent(event){
  console.log(
    `-> Mini-WAF has detected an event now!`.black.bgWhite + os.EOL +
    `   Triggered event by remote IP address: ${event.request.ip} at ${new Date().toLocaleString()}!`.yellow + os.EOL +
    `   Reason of audit action: ${event.reason.green}`.yellow + os.EOL +
    `   Method type: ${event.request.method.green}`.yellow + os.EOL +
    `   Port number: ${String(event.request.connection.localPort).green}`.yellow + os.EOL +
    `   Traffic direction: ${String((CheckFlags(event.wafComp.Directions, 0x01) && CheckFlags(event.wafComp.Directions, 0x02) ? 'Inbound | Outbound' : (CheckFlags(event.wafComp.Directions, 0x01) ? 'Inbound' : (CheckFlags(event.wafComp.Directions, 0x02) ? 'Outbound' : 'None')))).red}`.yellow + os.EOL +
    `   Event code: ${('0x' + Number(new Date().getTime() + Math.floor(10 ** 9 * Math.random())).toString(16)).yellow}\n`.green
  );
}

function WriteEventToLog(event, logType, fname) {
  fs.access(path.join(__dirname, 'mini-waf/', fname), fs.constants.F_OK, (err) => {
    let WriteCallback = () => {
      const wfstream = fs.createWriteStream(path.join(__dirname, 'mini-waf/', fname), { flags: 'a' });
      if (logType.toUpperCase() == 'BLOCK') {
        wfstream.write(
          `-> Mini-WAF has protected your server now!${os.EOL}
           Blocked triggered event by remote IP address: ${event.request.ip} at ${new Date().toLocaleString()}!${os.EOL}
           Reason of blocking action: ${event.reason}${os.EOL}
           Method type: ${event.request.method}${os.EOL}
           Port number: ${String(event.request.connection.localPort)}${os.EOL}
           Traffic direction: ${String((CheckFlags(event.wafComp.Directions, 0x01) && CheckFlags(event.wafComp.Directions, 0x02) ? 'Inbound | Outbound' : (CheckFlags(event.wafComp.Directions, 0x01) ? 'Inbound' : (CheckFlags(event.wafComp.Directions, 0x02) ? 'Outbound' : 'None'))))}
           Event code: ${('0x' + Number(new Date().getTime() + Math.floor(10 ** 9 * Math.random())).toString(16))}${os.EOL}${os.EOL}`
        );
      }
      else if (logType.toUpperCase() == 'AUDIT') {
        wfstream.write(
          `-> Mini-WAF has detected an event now!${os.EOL}
           Triggered event by remote IP address: ${event.request.ip} at ${new Date().toLocaleString()}!${os.EOL}
           Reason of audit action: ${event.reason}${os.EOL}
           Method type: ${event.request.method}${os.EOL}
           Port number: ${String(event.request.connection.localPort)}${os.EOL}
           Traffic direction: ${String((CheckFlags(event.wafComp.Directions, 0x01) && CheckFlags(event.wafComp.Directions, 0x02) ? 'Inbound | Outbound' : (CheckFlags(event.wafComp.Directions, 0x01) ? 'Inbound' : (CheckFlags(event.wafComp.Directions, 0x02) ? 'Outbound' : 'None'))))}
           Event code: ${('0x' + Number(new Date().getTime() + Math.floor(10 ** 9 * Math.random())).toString(16))}${os.EOL}${os.EOL}`
        );
      }
      wfstream.end();
    }
    if (!err) {
      WriteCallback();
    }
    else{
      fs.writeFile(path.join(__dirname, 'mini-waf/', fname), `#========================================= Mini-WAF Log File =========================================#${os.EOL}`, { flags: 'a' }, WriteCallback);
    }
  });
}

function ApplyArgument(oldArgs, newArg){
  let bFirst = true;
  let newArgs = [];
  for (let idx = 0; idx <= oldArgs.length; idx++){
    if (!bFirst){
      newArgs.push(oldArgs[String(idx-1)]);
    }
    else{
      bFirst = false;
      newArgs.push(newArg);
    }
  }
  return newArgs;
}

function Hook(targName, ptrStub, ptrParent){
  let PatchAddr = ptrParent[targName];
	let ptrHookObj = {
		TargetName: targName,
		Stub: ptrStub,
    Parent: ptrParent,
    PatchAddr: ptrParent[targName],
    OriginalFunction: function(){
      try {
        ptrParent[targName] = PatchAddr;
        let result = ptrParent[targName].apply(ptrParent, arguments);
        ptrParent[targName] = ptrStub;
        return result;
      } catch (e){ return; }
    },
    Unhook: function(){ ptrParent[targName] = PatchAddr; },
    Hook: function(){ ptrParent[targName] = ptrStub; }
  }
  Object.defineProperty(ptrStub, 'name', {name: targName});
  Object.defineProperty(ptrParent[targName], 'name', {name: targName});
	ptrParent[targName] = ptrStub;
	return ptrHookObj;
}



module.exports = {

  CheckFlags: CheckFlags,
  CookieParse: CookieParse,
  EnumAvailableFiles: EnumAvailableFiles,
  AddEntryInAccessTable: AddEntryInAccessTable,
  DisplayBlockedEvent: DisplayBlockedEvent,
  DisplayAuditEvent: DisplayAuditEvent,
  WriteEventToLog: WriteEventToLog,
  ApplyArgument: ApplyArgument,
  Hook: Hook

}
