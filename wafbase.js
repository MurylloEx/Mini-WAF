const Ip = require('ip');
const wafutils = require('./wafutils');
const concat = require('concat-stream');
const querystring = require('querystring');
const colors = require('colors');
const uuid = require('uuid').v4;
const CloneStream = require('readable-stream-clone/readable-stream-clone');

//---------------------------------------------------------------------------

const WAF_ASSERTION_OPERATOR = {
	OP_OR: 0x01,
	OP_AND: 0x02
}

const WAF_NETWORK_LAYER = {
	PROTOCOL_IPV4: 0x01,
	PROTOCOL_IPV6: 0x02
}

const WAF_MATCH_TYPE = {
	MATCH_IP: 0x01,
	MATCH_HEADERS: 0x02,
	MATCH_QUERY_STRING: 0x04,
	MATCH_PARAM_STRING: 0x08,
	MATCH_USER_AGENT: 0x10,
	MATCH_METHOD_TYPE: 0x20,
	MATCH_ATTEMPTS: 0x40,
	MATCH_PAYLOAD: 0x80,
	MATCH_COOKIES: 0x100,
	MATCH_FILE_EXT: 0x200,
	MATCH_ALL_SPECIFIED: 0x400 //Flag usada para comparações de WAF_MANAGE_TYPE.PERMIT onde todos os campos devem corresponder.
}

const WAF_MANAGE_TYPE = {
	PERMIT: 0x01,
	BLOCK: 0x02,
	AUDIT: 0x04
}

const WAF_RULE_DIRECTION = {
	INBOUND: 0x01,
	OUTBOUND: 0x02
}

//---------------------------------------------------------------------------

/**Middleware de nível de aplicação para uso do WAF.
 * 
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
 * 
 */
function WafMiddleware(wafObj) {
	return (req, res, next) => {

		//Define a nova propriedade do WAF nas requisições
		req.Blocked = false;
		res.Blocked = false;

		//Guarda as funções originais de I/O com decoradores __unhooked__original__
		res.__unhooked__original__send		= res.send;
		res.__unhooked__original__end		= res.end;
		res.__unhooked__original__write		= res.write;
		res.__unhooked__original__set		= res.set;
		res.__unhooked__original__header	= res.header;
		res.__unhooked__original__json		= res.json;
		res.__unhooked__original__jsonp		= res.jsonp;
		res.__unhooked__original__status	= res.status;
		
		res.Drop = function(){ req.Blocked = res.Blocked = true; res.__unhooked__original__status(403).__unhooked__original__end(); }

		let WafEngine = function () {
			let IpAddress = (req.headers['x-forwarded-for'] || '').split(',')[0] || req.connection.remoteAddress || req.socket.remoteAddress || req.connection.socket.remoteAddress || '';
			let cookies = wafutils.CookieParse(req.headers.cookie, {});
			let BlockStatus = false;
			let PermitStatus = false;
			let WafComponent = null;

			WafScanLoop:
			for (let k = 0; k < wafObj.Rules.length; k++) {
				let WafRule = wafObj.Rules[k];
				
				//DACLs of WAF
				for (let w = 0; w < WafRule.Dacls.length; w++) {

					let Dacl = WafRule.Dacls[w];

					let Ipv4MatchStatus = false;
					let Ipv6MatchStatus = false;
					let UserAgentsMatchStatus = false;
					let MethodTypesMatchStatus = false;

					if (WafCheckFlags(Dacl.NetworkLayers, WAF_NETWORK_LAYER.PROTOCOL_IPV4)) {
						Ipv4MatchStatus = (
							WafCheckFlags(Dacl.MatchTypes, WAF_MATCH_TYPE.MATCH_IP) &&
							Ip.isEqual(String(req.ip || IpAddress || ''), Dacl.Ipv4Address)
						);
					}

					if (WafCheckFlags(Dacl.NetworkLayers, WAF_NETWORK_LAYER.PROTOCOL_IPV6)) {
						Ipv6MatchStatus = (
							WafCheckFlags(Dacl.MatchTypes, WAF_MATCH_TYPE.MATCH_IP) &&
							Ip.isEqual(String(req.ip || IpAddress || ''), Dacl.Ipv6Address)
						);
					}

					if (WafCheckFlags(Dacl.MatchTypes, WAF_MATCH_TYPE.MATCH_METHOD_TYPE)) {
						let DaclMethodTypes = Dacl.MethodTypes.split('|');
						for (let j = 0; j < DaclMethodTypes.length; j++) {
							if (req.method.toUpperCase() == DaclMethodTypes[j].replace(/\s/g, '').toUpperCase()) {
								MethodTypesMatchStatus = true;
								break;
							}
						}
					}

					if (WafCheckFlags(Dacl.MatchTypes, WAF_MATCH_TYPE.MATCH_USER_AGENT) && !UserAgentsMatchStatus) {
						for (let x = 0; x < Dacl.UserAgents.RegexArray.length; x++) {
							if ((new RegExp(Dacl.UserAgents.RegexArray[x]).test(req.headers["user-agent"]))) {
								UserAgentsMatchStatus = true;
								break;
							}
						}
					}

					if (WafCheckFlags(Dacl.MatchTypes, WAF_MATCH_TYPE.MATCH_USER_AGENT) && !UserAgentsMatchStatus) {
						for (let x = 0; x < Dacl.UserAgents.MatchArray.length; x++) {
							if (req.headers['user-agent'].indexOf(Dacl.UserAgents.MatchArray[x], 0) !== -1) {
								UserAgentsMatchStatus = true;
								break;
							}
						}
					}

					//------------------------------------------------------------------------------

					if (WafCheckFlags(Dacl.Directions, WAF_RULE_DIRECTION.INBOUND)) {
						if (WafCheckFlags(Dacl.NetworkLayers, WAF_NETWORK_LAYER.PROTOCOL_IPV4) || WafCheckFlags(Dacl.NetworkLayers, WAF_NETWORK_LAYER.PROTOCOL_IPV6)) {

							let Hooks = [];

							let SendStub 		= function () { return Hooks[0].OriginalFunction.apply(res, arguments); }
							let EndStub 		= function () { return Hooks[1].OriginalFunction.apply(res, arguments); }
							let SetStub 		= function () { return Hooks[2].OriginalFunction.apply(res, arguments); }
							let HeaderStub 	= function () { return Hooks[3].OriginalFunction.apply(res, arguments); }
							let JsonStub 		= function () { return Hooks[4].OriginalFunction.apply(res, arguments); }
							let JsonpStub 	= function () { return Hooks[5].OriginalFunction.apply(res, arguments); }
							let WriteStub 	= function () { return Hooks[6].OriginalFunction.apply(res, arguments); }

							Hooks.push(wafutils.Hook('send', SendStub, res));
							Hooks.push(wafutils.Hook('end', EndStub, res));
							Hooks.push(wafutils.Hook('set', SetStub, res));
							Hooks.push(wafutils.Hook('header', HeaderStub, res));
							Hooks.push(wafutils.Hook('json', JsonStub, res));
							Hooks.push(wafutils.Hook('jsonp', JsonpStub, res));
							Hooks.push(wafutils.Hook('write', WriteStub, res));
							
							let Matchs = [
								{ Flag: WafCheckFlags(Dacl.MatchTypes, WAF_MATCH_TYPE.MATCH_IP), Match: WafCheckFlags(Dacl.NetworkLayers, WAF_NETWORK_LAYER.PROTOCOL_IPV4) ? Ipv4MatchStatus : (WafCheckFlags(Dacl.NetworkLayers, WAF_NETWORK_LAYER.PROTOCOL_IPV6) ? Ipv6MatchStatus : false) },
								{ Flag: WafCheckFlags(Dacl.MatchTypes, WAF_MATCH_TYPE.MATCH_USER_AGENT), Match: UserAgentsMatchStatus },
								{ Flag: WafCheckFlags(Dacl.MatchTypes, WAF_MATCH_TYPE.MATCH_METHOD_TYPE), Match: MethodTypesMatchStatus }
							];

							let Assertions = WafTranslateAssertions(Matchs);

							Hooks[1].Unhook();

							//Check all matches and pass through or block the request.
							switch (Dacl.ManageType) {
								case WAF_MANAGE_TYPE.PERMIT:
									if (!WafCheckFlags(Dacl.MatchTypes, WAF_MATCH_TYPE.MATCH_ALL_SPECIFIED)) {
										//Permitir se ao menos uma condição Dacl for atendida.
										if (WafCheckAssertions(Assertions, WAF_ASSERTION_OPERATOR.OP_OR, false)) {
											//Passar adiante para a próxima DACL.
											PermitStatus = true;
											WafComponent = Dacl;
											break WafScanLoop;
										}
									}
									else {
										//Permitir somente se todas as condições da Dacl forem atendidas.
										if (WafCheckAssertions(Assertions, WAF_ASSERTION_OPERATOR.OP_AND, false)) {
											//Passar adiante para a próxima DACL.
											PermitStatus = true;
											WafComponent = Dacl;
											break WafScanLoop;
										}
									}
									break;
								case WAF_MANAGE_TYPE.BLOCK:
									if (!WafCheckFlags(Dacl.MatchTypes, WAF_MATCH_TYPE.MATCH_ALL_SPECIFIED)) {
										//Bloquear se ao menos uma condição Dacl for atendida.
										if (WafCheckAssertions(Assertions, WAF_ASSERTION_OPERATOR.OP_OR, false)) {
											//Bloquear a requisição.
											BlockStatus = true;
											WafComponent = Dacl;
										}
									}
									else {
										//Bloquear somente se todas as condições da Dacl forem atendidas.
										if (WafCheckAssertions(Assertions, WAF_ASSERTION_OPERATOR.OP_AND, false)) {
											//Bloquear a requisição.
											BlockStatus = true;
											WafComponent = Dacl;
										}
									}
									break;
								case WAF_MANAGE_TYPE.AUDIT:
									//Passar a requisição mas adicionar ao log os eventos.
									break;
								default:
								//Remover Dacl inválida pois não tem forma de gerenciamento definida.
							}

							Hooks[1].Hook();

						}
						else {
							//Remover Dacl inválida pois não tem um protocolo de rede definido.
						}
					}

					if (WafCheckFlags(Dacl.Directions, WAF_RULE_DIRECTION.OUTBOUND)) {
						//Criar ganchos nas funções de saída;
						if (WafCheckFlags(Dacl.NetworkLayers, WAF_NETWORK_LAYER.PROTOCOL_IPV4) ||	WafCheckFlags(Dacl.NetworkLayers, WAF_NETWORK_LAYER.PROTOCOL_IPV6)) {

							let ScanOutbound = function() {
								let Matchs = [
									{ Flag: WafCheckFlags(Dacl.MatchTypes, WAF_MATCH_TYPE.MATCH_IP), Match: WafCheckFlags(Dacl.NetworkLayers, WAF_NETWORK_LAYER.PROTOCOL_IPV4) ? Ipv4MatchStatus : (WafCheckFlags(Dacl.NetworkLayers, WAF_NETWORK_LAYER.PROTOCOL_IPV6) ? Ipv6MatchStatus : false) },
									{ Flag: WafCheckFlags(Dacl.MatchTypes, WAF_MATCH_TYPE.MATCH_USER_AGENT), Match: UserAgentsMatchStatus },
									{ Flag: WafCheckFlags(Dacl.MatchTypes, WAF_MATCH_TYPE.MATCH_METHOD_TYPE), Match: MethodTypesMatchStatus }
								];
	
								let Assertions = WafTranslateAssertions(Matchs);
	
								Hooks[1].Unhook();

								//Check all matches and pass through or block the request.
								switch (Dacl.ManageType) {
									case WAF_MANAGE_TYPE.PERMIT:
										if (!WafCheckFlags(Dacl.MatchTypes, WAF_MATCH_TYPE.MATCH_ALL_SPECIFIED)) {
											//Permitir se ao menos uma condição Dacl for atendida.
											if (WafCheckAssertions(Assertions, WAF_ASSERTION_OPERATOR.OP_OR, false)) {
												//Passar adiante para a próxima DACL.
											}
											else {
												//Bloquear a requisição.
												WafBlockConnection(req, res, Dacl);
											}
										}
										else {
											//Permitir somente se todas as condições da Dacl forem atendidas.
											if (WafCheckAssertions(Assertions, WAF_ASSERTION_OPERATOR.OP_AND, false)) {
												//Passar adiante para a próxima DACL.
											}
											else {
												//Bloquear a requisição.
												WafBlockConnection(req, res, Dacl);
											}
										}
										break;
									case WAF_MANAGE_TYPE.BLOCK:
										if (!WafCheckFlags(Dacl.MatchTypes, WAF_MATCH_TYPE.MATCH_ALL_SPECIFIED)) {
											//Bloquear se ao menos uma condição Dacl for atendida.
											if (WafCheckAssertions(Assertions, WAF_ASSERTION_OPERATOR.OP_OR, false)) {
												//Bloquear a requisição.
												WafBlockConnection(req, res, Dacl);
											}
											else {
												//Passar adiante para a próxima DACL.
											}
										}
										else {
											//Bloquear somente se todas as condições da Dacl forem atendidas.
											if (WafCheckAssertions(Assertions, WAF_ASSERTION_OPERATOR.OP_AND, false)) {
												//Bloquear a requisição.
												WafBlockConnection(req, res, Dacl);
											}
											else {
												//Passar adiante para a próxima DACL.
											}
										}
										break;
									case WAF_MANAGE_TYPE.AUDIT:
										//Passar a requisição mas adicionar ao log os eventos.
										break;
									default:
									//Remover Dacl inválida pois não tem forma de gerenciamento definida.
								}

								Hooks[1].Hook();
							}

							let Hooks = [];

							let SendStub 		= function(){ if(res.Blocked){ return; } ScanOutbound.apply(this, arguments); return Hooks[0].OriginalFunction.apply(res, arguments); }
							let EndStub 		= function(){ if(res.Blocked){ return; } ScanOutbound.apply(this, arguments); return Hooks[1].OriginalFunction.apply(res, arguments); }
							let SetStub 		= function(){ if(res.Blocked){ return; } ScanOutbound.apply(this, arguments); return Hooks[2].OriginalFunction.apply(res, arguments); }
							let HeaderStub 	= function(){ if(res.Blocked){ return; } ScanOutbound.apply(this, arguments); return Hooks[3].OriginalFunction.apply(res, arguments); }
							let JsonStub 		= function(){ if(res.Blocked){ return; } ScanOutbound.apply(this, arguments); return Hooks[4].OriginalFunction.apply(res, arguments); }
							let JsonpStub 	= function(){ if(res.Blocked){ return; } ScanOutbound.apply(this, arguments); return Hooks[5].OriginalFunction.apply(res, arguments); }
							let WriteStub		= function(){ if(res.Blocked){ return; } ScanOutbound.apply(this, arguments); return Hooks[6].OriginalFunction.apply(res, arguments); }

							Hooks.push(wafutils.Hook('send', SendStub, res));
							Hooks.push(wafutils.Hook('end', EndStub, res));
							Hooks.push(wafutils.Hook('set', SetStub, res));
							Hooks.push(wafutils.Hook('header', HeaderStub, res));
							Hooks.push(wafutils.Hook('json', JsonStub, res));
							Hooks.push(wafutils.Hook('jsonp', JsonpStub, res));
							Hooks.push(wafutils.Hook('write', WriteStub, res));
							
						}
						else {
							//Remover Dacl inválida pois não tem um protocolo de rede definido.
						}
					}

					//------------------------------------------------------------------------------

				}

				//Filters of WAF
				for (let z = 0; z < WafRule.Filters.length; z++) {

					let Filter = WafRule.Filters[z];

					let HeadersMatchStatus = false;
					let QueryStringsMatchStatus = false;
					let CookiesMatchStatus = false;
					let ParamStringsMatchStatus = false;
					let PayloadsMatchStatus = false;
					let FileExtensionsMatchStatus = false;
					let AttemptsMatchStatus = false;

					let ExploitationAttempt = false;

					if (WafCheckFlags(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_HEADERS)) {
						if (!HeadersMatchStatus) {
							for (let x = 0; x < Filter.Headers.NameArray.length; x++) {
								if (req.get(Filter.Headers.NameArray[x].toLowerCase()) !== undefined) {
									HeadersMatchStatus = true;
									break;
								}
							}
						}
						if (!HeadersMatchStatus) {
							for (let x = 0; x < Filter.Headers.RegexArray.length; x++) {
								for (let header in req.headers) {
									if ((new RegExp(Filter.Headers.RegexArray[x]).test(req.headers[header]))) {
										HeadersMatchStatus = true;
										x = Filter.Headers.RegexArray.length;
										break;
									}
								}
							}
						}
						if (!HeadersMatchStatus) {
							for (let x = 0; x < Filter.Headers.MatchArray.length; x++) {
								for (let header in req.headers) {
									if (req.headers[header].indexOf(Filter.Headers.MatchArray[x], 0) !== -1) {
										HeadersMatchStatus = true;
										x = Filter.Headers.MatchArray.length;
										break;
									}
								}
							}
						}
					}

					if (WafCheckFlags(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_QUERY_STRING)) {
						if (!QueryStringsMatchStatus) {
							for (let x = 0; x < Filter.QueryStrings.NameArray.length; x++) {
								for (let querykey in req.query) {
									if (Filter.QueryStrings.NameArray[x] == querykey) {
										QueryStringsMatchStatus = true;
										x = Filter.QueryStrings.NameArray.length;
										break;
									}
								}
							}
						}
						if (!QueryStringsMatchStatus) {
							for (let x = 0; x < Filter.QueryStrings.RegexArray.length; x++) {
								for (let querykey in req.query) {
									if (new RegExp(Filter.QueryStrings.RegexArray[x]).test(req.query[querykey])) {
										QueryStringsMatchStatus = true;
										x = Filter.QueryStrings.RegexArray.length;
										break;
									}
								}
							}
						}
						if (!QueryStringsMatchStatus) {
							for (let x = 0; x < Filter.QueryStrings.MatchArray.length; x++) {
								for (let querykey in req.query) {
									if (req.query[querykey].indexOf(Filter.QueryStrings.MatchArray[x], 0) !== -1) {
										QueryStringsMatchStatus = true;
										x = Filter.QueryStrings.MatchArray.length;
										break;
									}
								}
							}
						}
					}

					if (WafCheckFlags(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_COOKIES)) {
						if (!CookiesMatchStatus) {
							for (let x = 0; x < Filter.Cookies.NameArray.length; x++) {
								for (let cookiekey in cookies) {
									if (Filter.Cookies.NameArray[x] == cookiekey) {
										CookiesMatchStatus = true;
										x = Filter.Cookies.NameArray.length;
										break;
									}
								}
							}
						}
						if (!CookiesMatchStatus) {
							for (let x = 0; x < Filter.Cookies.RegexArray.length; x++) {
								for (let cookiekey in cookies) {
									if (new RegExp(Filter.Cookies.RegexArray[x]).test(cookies[cookiekey])) {
										CookiesMatchStatus = true;
										x = Filter.Cookies.RegexArray.length;
										break;
									}
								}
							}
						}
						if (!CookiesMatchStatus) {
							for (let x = 0; x < Filter.Cookies.MatchArray.length; x++) {
								for (let cookiekey in cookies) {
									if (cookies[cookiekey].indexOf(Filter.Cookies.MatchArray[x], 0) !== -1) {
										CookiesMatchStatus = true;
										x = Filter.Cookies.MatchArray.length;
										break;
									}
								}
							}
						}
					}

					if (WafCheckFlags(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_PARAM_STRING)) {
						if (!ParamStringsMatchStatus) {
							let Params = req.url.match('^[^?]*')[0].split('/').slice(1);
							let breakSearch = false;
							for (let p_idx = 0; p_idx < Params.length; p_idx++) {
								if (!breakSearch) {
									for (let idx = 0; idx < Filter.ParamStrings.RegexArray.length; idx++) {
										try {
											if (new RegExp(Filter.ParamStrings.RegexArray[idx]).test(querystring.unescape(Params[p_idx]))) {
												ParamStringsMatchStatus = true;
												breakSearch = true;
												break;
											}
										} catch (e) { }
									}
								}
								else {
									break;
								}
							}
						}
						if (!ParamStringsMatchStatus) {
							let Params = req.url.match('^[^?]*')[0].split('/').slice(1);
							let breakSearch = false;
							for (let p_idx = 0; p_idx < Params.length; p_idx++) {
								if (!breakSearch) {
									for (let idx = 0; idx < Filter.ParamStrings.MatchArray.length; idx++) {
										try {
											if (querystring.unescape(Params[p_idx]).indexOf(Filter.ParamStrings.MatchArray[idx], 0) !== -1) {
												ParamStringsMatchStatus = true;
												breakSearch = true;
												break;
											}
										} catch (e) { }
									}
								}
								else {
									break;
								}
							}
						}
					}

					if (WafCheckFlags(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_PAYLOAD)) {
						if (!PayloadsMatchStatus) {
							for (let x = 0; x < Filter.Payloads.RegexArray.length; x++) {
								if ((new RegExp(Filter.Payloads.RegexArray[x])).test(req.rawBody)) {
									PayloadsMatchStatus = true;
									break;
								}
							}
						}
						if (!PayloadsMatchStatus) {
							for (let x = 0; x < Filter.Payloads.MatchArray.length; x++) {
								if (req.rawBody.indexOf(Filter.Payloads.MatchArray[x], 0) !== -1) {
									PayloadsMatchStatus = true;
									break;
								}
							}
						}
					}

					if (WafCheckFlags(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_FILE_EXT)) {
						if (req.files) {
							if (!FileExtensionsMatchStatus) {
								try {
									let regExpNullChr = new RegExp(/\x00/);
									let matchFinal = false;
									wafutils.EnumAvailableFiles(req, (finfo, fname, drop) => {
										if (regExpNullChr.test(fname)) {
											//Possible null-based attack attempt.
											ExploitationAttempt = true;
											drop();
										}
										else {
											let fparts = fname.split('.');
											let fext = fparts[fparts.length - 1];
											for (let idx = 0; idx < Filter.FileExtensions.ExtensionArray.length; idx++) {
												if (WafCheckFlags(Filter.ManageType, WAF_MATCH_TYPE.MATCH_ALL_SPECIFIED)) {
													//All file extensions should match the patterns of the filter.
													if (idx == 0) {
														matchFinal = (fext.toUpperCase() == Filter.FileExtensions.ExtensionArray[idx].toUpperCase());
													}
													else {
														matchFinal = matchFinal && (fext.toUpperCase() == Filter.FileExtensions.ExtensionArray[idx].toUpperCase());
													}
												}
												else {
													//At least one file extension should match the patterns of the filter.
													if (fext.toUpperCase() == Filter.FileExtensions.ExtensionArray[idx].toUpperCase()) {
														matchFinal = true;
														idx = Filter.FileExtensions.ExtensionArray.length;
														drop();
													}
												}
											}
										}
									});
									FileExtensionsMatchStatus = matchFinal;
								} catch (e) { }
							}
							if (!FileExtensionsMatchStatus) {
								try {
									let regExpNullChr = new RegExp(/\x00/);
									let matchFinal = false;
									wafutils.EnumAvailableFiles(req, (finfo, fname, drop) => {
										if (regExpNullChr.test(fname)) {
											//Possible null-based attack attempt.
											ExploitationAttempt = true;
											drop();
										}
										else {
											let fparts = fname.split('.');
											let fext = fparts[fparts.length - 1];
											for (let idx = 0; idx < Filter.FileExtensions.RegexArray.length; idx++) {
												if (WafCheckFlags(Filter.ManageType, WAF_MATCH_TYPE.MATCH_ALL_SPECIFIED)) {
													//All file extensions should match the patterns of the filter.
													if (idx == 0) {
														matchFinal = new RegExp(Filter.FileExtensions.RegexArray[idx]).test(fext);
													}
													else {
														matchFinal = matchFinal && new RegExp(Filter.FileExtensions.RegexArray[idx]).test(fext);
													}
												}
												else {
													//At least one file extension should match the patterns of the filter.
													if (new RegExp(Filter.FileExtensions.RegexArray[idx]).test(fext)) {
														matchFinal = true;
														idx = Filter.FileExtensions.RegexArray.length;
														drop();
													}
												}
											}
										}
									});
									FileExtensionsMatchStatus = matchFinal;
								} catch (e) { }
							}
							if (!FileExtensionsMatchStatus) {
								try {
									let regExpNullChr = new RegExp(/\x00/);
									let matchFinal = false;
									wafutils.EnumAvailableFiles(req, (finfo, fname, drop) => {
										if (regExpNullChr.test(fname)) {
											//Possible null-based attack attempt.
											ExploitationAttempt = true;
											drop();
										}
										else {
											let fparts = fname.split('.');
											let fext = fparts[fparts.length - 1];
											for (let idx = 0; idx < Filter.FileExtensions.MatchArray.length; idx++) {
												if (WafCheckFlags(Filter.ManageType, WAF_MATCH_TYPE.MATCH_ALL_SPECIFIED)) {
													//All file extensions should match the patterns of the filter.
													if (idx == 0) {
														matchFinal = (fext.indexOf(Filter.FileExtensions.MatchArray[idx], 0) !== -1);
													}
													else {
														matchFinal = matchFinal && (fext.indexOf(Filter.FileExtensions.MatchArray[idx], 0) !== -1);
													}
												}
												else {
													//At least one file extension should match the patterns of the filter.
													if (fext.indexOf(Filter.FileExtensions.MatchArray[idx], 0) !== -1) {
														matchFinal = true;
														idx = Filter.FileExtensions.MatchArray.length;
														drop();
													}
												}
											}
										}
									});
									FileExtensionsMatchStatus = matchFinal;
								} catch (e) { }
							}
						}
					}

					if (WafCheckFlags(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_ATTEMPTS)) {
						try {
							if (Ip.isV4Format(req.ip) || Ip.isV6Format(req.ip)){
								let attemptAccess = {};
								if (Ip.isV4Format(req.ip) && WafCheckFlags(Filter.NetworkLayers, WAF_NETWORK_LAYER.PROTOCOL_IPV4)) {
									attemptAccess = wafutils.AddEntryInAccessTable(wafObj, Filter, req.ip, WAF_NETWORK_LAYER.PROTOCOL_IPV4);
								}
								if (Ip.isV6Format(req.ip) && WafCheckFlags(Filter.NetworkLayers, WAF_NETWORK_LAYER.PROTOCOL_IPV6)) {
									attemptAccess = wafutils.AddEntryInAccessTable(wafObj, Filter, req.ip, WAF_NETWORK_LAYER.PROTOCOL_IPV6);
								}
								if (attemptAccess.Exceeded == true){
									AttemptsMatchStatus = true;
								}
								res.set('X-RateLimit-Limit', Filter.Attempts.MaxAttempts);
								res.set('X-RateLimit-Remaining', attemptAccess.RemainingAttempts);
								res.set('X-RateLimit-Current', attemptAccess.CurrentAttempts);
							}
						} catch (e) { }
					}

					//------------------------------------------------------------------------------

					if (WafCheckFlags(Filter.Directions, WAF_RULE_DIRECTION.INBOUND)) {
						if (WafCheckFlags(Filter.NetworkLayers, WAF_NETWORK_LAYER.PROTOCOL_IPV4) ||	WafCheckFlags(Filter.NetworkLayers, WAF_NETWORK_LAYER.PROTOCOL_IPV6)) {

							let Matchs = [
								{ Flag: WafCheckFlags(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_HEADERS), Match: HeadersMatchStatus },
								{ Flag: WafCheckFlags(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_QUERY_STRING), Match: QueryStringsMatchStatus },
								{ Flag: WafCheckFlags(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_COOKIES), Match: CookiesMatchStatus },
								{ Flag: WafCheckFlags(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_PARAM_STRING), Match: ParamStringsMatchStatus },
								{ Flag: WafCheckFlags(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_PAYLOAD), Match: PayloadsMatchStatus },
								{ Flag: WafCheckFlags(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_FILE_EXT), Match: FileExtensionsMatchStatus },
								{ Flag: WafCheckFlags(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_ATTEMPTS), Match: AttemptsMatchStatus }
							];

							let Assertions = WafTranslateAssertions(Matchs);

							//Check all matches and pass through or block the request.
							switch(Filter.ManageType){
								case WAF_MANAGE_TYPE.PERMIT:
									if (!ExploitationAttempt) {
										if (!WafCheckAssertions(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_ALL_SPECIFIED)) {
											//Permitir se ao menos uma condição do Filtro for atendida.
											if (WafCheckAssertions(Assertions, WAF_ASSERTION_OPERATOR.OP_OR, false)) {
												//Passar adiante para o próximo filtro
												PermitStatus = true;
												WafComponent = Filter;
												break WafScanLoop;
											}
										}
										else {
											//Permitir somente se todas as condições do Filtro forem atendidas.
											if (WafCheckAssertions(Assertions, WAF_ASSERTION_OPERATOR.OP_AND, false)) {
												//Passar adiante para o próximo Filtro.
												PermitStatus = true;
												WafComponent = Filter;
												break WafScanLoop;
											}
										}
									}
									else{
										//Bloquear a requisição.
										BlockStatus = true;
										WafComponent = Filter;
									}
									break;
								case WAF_MANAGE_TYPE.BLOCK:
									if (!ExploitationAttempt){
										if (!WafCheckFlags(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_ALL_SPECIFIED)) {
											//Bloquear se ao menos uma condição do Filtro for atendida.
											if (WafCheckAssertions(Assertions, WAF_ASSERTION_OPERATOR.OP_OR, false)) {
												//Bloquear a requisição.
												BlockStatus = true;
												WafComponent = Filter;
											}
										}
										else {
											//Bloquear somente se todas as condições do Filtro forem atendidas.
											if (WafCheckAssertions(Assertions, WAF_ASSERTION_OPERATOR.OP_AND, false)) {
												//Bloquear a requisição.
												BlockStatus = true;
												WafComponent = Filter;
											}
										}
									}
									else{
										//Bloquear a requisição.
										BlockStatus = true;
										WafComponent = Filter;
									}
									break;
								case WAF_MANAGE_TYPE.AUDIT:
									//Passar a requisição mas adicionar ao log os eventos.
									break;
							}
						}
						else{
							//Remover filtro inválido, sem protocolo IP definido.
							//Ou ignorar o filtro inválido.
						}

					}

					if (WafCheckFlags(Filter.Directions, WAF_RULE_DIRECTION.OUTBOUND)) {
						//Criar ganchos nas funções de saída;

						if (WafCheckFlags(Filter.NetworkLayers, WAF_NETWORK_LAYER.PROTOCOL_IPV4) ||	WafCheckFlags(Filter.NetworkLayers, WAF_NETWORK_LAYER.PROTOCOL_IPV6)) {

							let Hooks = [];

							let ScanOutbound = function() {

								HeadersMatchStatus = false;
								PayloadsMatchStatus = false;

								switch (arguments['0']){
									case 0:
										if (typeof arguments['1'] == 'string'){
											if (!PayloadsMatchStatus) {
												for (let x = 0; x < Filter.Payloads.RegexArray.length; x++) {
													if (new RegExp(Filter.Payloads.RegexArray[x]).test(arguments['1'])) {
														PayloadsMatchStatus = true;
														break;
													}
												}
											}
											if (!PayloadsMatchStatus) {
												for (let x = 0; x < Filter.Payloads.MatchArray.length; x++) {
													if (arguments['1'].indexOf(Filter.Payloads.MatchArray[x], 0) !== -1) {
														PayloadsMatchStatus = true;
														break;
													}
												}
											}
										}
										break;
									case 1:
										if (arguments.length >= 2) {
											let EndData = null;
											switch (typeof arguments['1']) {
												case 'object':
													try {
														EndData = JSON.stringify(arguments['1']);
													} catch (e) { }
													break;
												case 'string':
													EndData = arguments['1'];
													break;
											}
											if (EndData != null) {
												if (!PayloadsMatchStatus) {
													for (let x = 0; x < Filter.Payloads.RegexArray.length; x++) {
														if (new RegExp(Filter.Payloads.RegexArray[x]).test(EndData)) {
															PayloadsMatchStatus = true;
															break;
														}
													}
												}
												if (!PayloadsMatchStatus) {
													for (let x = 0; x < Filter.Payloads.MatchArray.length; x++) {
														if (EndData.indexOf(Filter.Payloads.MatchArray[x], 0) !== -1) {
															PayloadsMatchStatus = true;
															break;
														}
													}
												}
											}
										}
										break;
									case 2:
										let FieldName = null;
										let FieldValue = null;
										if (arguments.length == 2){
											FieldName = arguments['1'];
										}
										else{
											if (arguments.length == 3){
												FieldName = arguments['1'];
												if (typeof arguments['2'] == 'string'){
													FieldValue = arguments['2'];
												}
											}
										}
										if (FieldName != null) {
											if (!HeadersMatchStatus) {
												for (let x = 0; x < Filter.Headers.NameArray.length; x++) {
													if (Filter.Headers.NameArray[x].toLowerCase() == FieldName.toLowerCase()) {
														HeadersMatchStatus = true;
														break;
													}
												}
											}
										}
										if (FieldValue != null) {
											if (!HeadersMatchStatus) {
												for (let x = 0; x < Filter.Headers.RegexArray.length; x++) {
													if ((new RegExp(Filter.Headers.RegexArray[x]).test(FieldValue))) {
														HeadersMatchStatus = true;
														break;
													}
												}
											}
											if (!HeadersMatchStatus) {
												for (let x = 0; x < Filter.Headers.MatchArray.length; x++) {
													if (FieldValue.indexOf(Filter.Headers.MatchArray[x], 0) !== -1) {
														HeadersMatchStatus = true;
														break;
													}
												}
											}
										}
										break;
									case 3:
										let HeaderName = null;
										let HeaderValue = null;
										if (arguments.length == 2){
											HeaderName = arguments['1'];
										}
										else{
											if (arguments.length == 3){
												HeaderName = arguments['1'];
												if (typeof arguments['2'] == 'string'){
													HeaderValue = arguments['2'];
												}
											}
										}
										if (HeaderName != null) {
											if (!HeadersMatchStatus) {
												for (let x = 0; x < Filter.Headers.NameArray.length; x++) {
													if (Filter.Headers.NameArray[x].toLowerCase() == HeaderName.toLowerCase()) {
														HeadersMatchStatus = true;
														break;
													}
												}
											}
										}
										if (HeaderValue != null) {
											if (!HeadersMatchStatus) {
												for (let x = 0; x < Filter.Headers.RegexArray.length; x++) {
													if ((new RegExp(Filter.Headers.RegexArray[x]).test(HeaderValue))) {
														HeadersMatchStatus = true;
														break;
													}
												}
											}
											if (!HeadersMatchStatus) {
												for (let x = 0; x < Filter.Headers.MatchArray.length; x++) {
													if (HeaderValue.indexOf(Filter.Headers.MatchArray[x], 0) !== -1) {
														HeadersMatchStatus = true;
														break;
													}
												}
											}
										}
										break;
									case 4:
										if (arguments.length == 2){
											try{
												let JsonData = JSON.parse(arguments['1']);
												if (!PayloadsMatchStatus) {
													for (let x = 0; x < Filter.Payloads.RegexArray.length; x++) {
														if (new RegExp(Filter.Payloads.RegexArray[x]).test(JsonData)) {
															PayloadsMatchStatus = true;
															break;
														}
													}
												}
												if (!PayloadsMatchStatus) {
													for (let x = 0; x < Filter.Payloads.MatchArray.length; x++) {
														if (JsonData.indexOf(Filter.Payloads.MatchArray[x], 0) !== -1) {
															PayloadsMatchStatus = true;
															break;
														}
													}
												}
											} catch (e) {}
										}
										break;
									case 5:
										if (arguments.length == 2){
											try{
												let JsonpData = JSON.parse(arguments['1']);
												if (!PayloadsMatchStatus) {
													for (let x = 0; x < Filter.Payloads.RegexArray.length; x++) {
														if (new RegExp(Filter.Payloads.RegexArray[x]).test(JsonpData)) {
															PayloadsMatchStatus = true;
															break;
														}
													}
												}
												if (!PayloadsMatchStatus) {
													for (let x = 0; x < Filter.Payloads.MatchArray.length; x++) {
														if (JsonpData.indexOf(Filter.Payloads.MatchArray[x], 0) !== -1) {
															PayloadsMatchStatus = true;
															break;
														}
													}
												}
											} catch (e) {}
										}
										break;
									case 6:
										if (arguments.length >= 2) {
											let WriteData = null;
											switch (typeof arguments['1']) {
												case 'object':
													try {
														WriteData = JSON.stringify(arguments['1']);
													} catch (e) { }
													break;
												case 'string':
													WriteData = arguments['1'];
													break;
											}
											if (WriteData != null) {
												if (!PayloadsMatchStatus) {
													for (let x = 0; x < Filter.Payloads.RegexArray.length; x++) {
														if (new RegExp(Filter.Payloads.RegexArray[x]).test(WriteData)) {
															PayloadsMatchStatus = true;
															break;
														}
													}
												}
												if (!PayloadsMatchStatus) {
													for (let x = 0; x < Filter.Payloads.MatchArray.length; x++) {
														if (WriteData.indexOf(Filter.Payloads.MatchArray[x], 0) !== -1) {
															PayloadsMatchStatus = true;
															break;
														}
													}
												}
											}
										}
										break;
								}

								let Matchs = [
									{ Flag: WafCheckFlags(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_HEADERS), Match: HeadersMatchStatus },
									{ Flag: WafCheckFlags(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_QUERY_STRING), Match: QueryStringsMatchStatus },
									{ Flag: WafCheckFlags(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_COOKIES), Match: CookiesMatchStatus },
									{ Flag: WafCheckFlags(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_PARAM_STRING), Match: ParamStringsMatchStatus },
									{ Flag: WafCheckFlags(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_PAYLOAD), Match: PayloadsMatchStatus },
									{ Flag: WafCheckFlags(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_FILE_EXT), Match: FileExtensionsMatchStatus },
									{ Flag: WafCheckFlags(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_ATTEMPTS), Match: AttemptsMatchStatus }
								];

								let Assertions = WafTranslateAssertions(Matchs);
	
								Hooks[1].Unhook();

								//Check all matches and pass through or block the request.
								switch(Filter.ManageType){
									case WAF_MANAGE_TYPE.PERMIT:
										if (!ExploitationAttempt) {
											if (!WafCheckAssertions(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_ALL_SPECIFIED)) {
												//Permitir se ao menos uma condição do Filtro for atendida.
												if (WafCheckAssertions(Assertions, WAF_ASSERTION_OPERATOR.OP_OR, false)) {
													//Passar adiante para o próximo filtro
												}
												else {
													//Bloquear a requisição.
													WafBlockConnection(req, res, Filter);
												}
											}
											else {
												//Permitir somente se todas as condições do Filtro forem atendidas.
												if (WafCheckAssertions(Assertions, WAF_ASSERTION_OPERATOR.OP_AND, false)) {
													//Passar adiante para o próximo Filtro.
												}
												else {
													//Bloquear a requisição.
													WafBlockConnection(req, res, Filter);
												}
											}
										}
										else{
											//Bloquear a requisição.
											WafBlockConnection(req, res, Filter);
										}
										break;
									case WAF_MANAGE_TYPE.BLOCK:
										if (!ExploitationAttempt){
											if (!WafCheckFlags(Filter.MatchTypes, WAF_MATCH_TYPE.MATCH_ALL_SPECIFIED)) {
												//Bloquear se ao menos uma condição do Filtro for atendida.
												if (WafCheckAssertions(Assertions, WAF_ASSERTION_OPERATOR.OP_OR, false)) {
													//Bloquear a requisição.
													WafBlockConnection(req, res, Filter);
												}
											}
											else {
												//Bloquear somente se todas as condições do Filtro forem atendidas.
												if (WafCheckAssertions(Assertions, WAF_ASSERTION_OPERATOR.OP_AND, false)) {
													//Bloquear a requisição.
													WafBlockConnection(req, res, Filter);
												}
											}
										}
										else{
											//Bloquear a requisição.
											WafBlockConnection(req, res, Filter);
										}
										break;
									case WAF_MANAGE_TYPE.AUDIT:
										//Passar a requisição mas adicionar ao log os eventos.
										break;
								}

								Hooks[1].Hook();
							}
							
							let SendStub 		= function(){ if(res.Blocked){ return; } ScanOutbound.apply(this, wafutils.ApplyArgument(arguments, 0)); return Hooks[0].OriginalFunction.apply(res, arguments); }
							let EndStub 		= function(){ if(res.Blocked){ return; } ScanOutbound.apply(this, wafutils.ApplyArgument(arguments, 1)); return Hooks[1].OriginalFunction.apply(res, arguments); }
							let SetStub 		= function(){ if(res.Blocked){ return; } ScanOutbound.apply(this, wafutils.ApplyArgument(arguments, 2)); return Hooks[2].OriginalFunction.apply(res, arguments); }
							let HeaderStub 	= function(){ if(res.Blocked){ return; } ScanOutbound.apply(this, wafutils.ApplyArgument(arguments, 3)); return Hooks[3].OriginalFunction.apply(res, arguments); }
							let JsonStub 		= function(){ if(res.Blocked){ return; } ScanOutbound.apply(this, wafutils.ApplyArgument(arguments, 4)); return Hooks[4].OriginalFunction.apply(res, arguments); }
							let JsonpStub 	= function(){ if(res.Blocked){ return; } ScanOutbound.apply(this, wafutils.ApplyArgument(arguments, 5)); return Hooks[5].OriginalFunction.apply(res, arguments); }
							let WriteStub		= function(){ if(res.Blocked){ return; } ScanOutbound.apply(this, wafutils.ApplyArgument(arguments, 6)); return Hooks[6].OriginalFunction.apply(res, arguments); }
							
							//I/O hooks in firewall Middleware
							Hooks.push(wafutils.Hook('send', 	 SendStub, 	 res));
							Hooks.push(wafutils.Hook('end', 	 EndStub, 	 res));
							Hooks.push(wafutils.Hook('set', 	 SetStub, 	 res));
							Hooks.push(wafutils.Hook('header', HeaderStub, res));
							Hooks.push(wafutils.Hook('json', 	 JsonStub, 	 res));
							Hooks.push(wafutils.Hook('jsonp',  JsonpStub,  res));
							Hooks.push(wafutils.Hook('write',  WriteStub,  res));
							
						}
						else {
							//Remover Filtro inválido pois não tem um protocolo de rede definido.
						}
					}

					//------------------------------------------------------------------------------

				}
			}

			if (PermitStatus || !BlockStatus){
				for (let idx = 0; idx < wafObj.Callbacks.length; idx++){
					if (res.Blocked && req.Blocked){
						break;
					}
					wafObj.Callbacks[idx].Callback(req, res);
				}
				if (!req.Blocked && !res.Blocked){
					//Call the next Middleware registered.
					next();
				}
			}
			else{
				//Block incoming connection.
				WafBlockConnection(req, res, WafComponent);
			}
			
		}

		let cloned = new CloneStream(req);
		let reqcloned = new CloneStream(req);
		cloned.pipe(concat(function(data){
			req.rawBody = data.toString('utf8');
			for (let obj in reqcloned){
				if (typeof req[obj] != "undefined"){
					 req[obj] = reqcloned[obj];
				}
			}
		})).on('finish', () => {
			WafEngine();
		});

	}
}

/**Middleware de políticas de segurança para navegadores.
 * @see https://owasp.org/www-project-secure-headers/
 */
function WafSecurityPolicy() {
	return (req, res, next) => {
		res.set('X-Frame-Options', 'sameorigin');
		res.set('X-XSS-Protection', '1');
		res.set('X-Content-Type-Options', 'nosniff');
		res.removeHeader('X-Powered-By');
		res.removeHeader('Server');
		if (req.method.toUpperCase() == 'OPTIONS') {
			if (typeof req.get('Origin') != "undefined" ) {
				res.set('Access-Control-Allow-Origin', req.get('Origin'));
			}
			if (typeof req.get('Access-Control-Request-Method') != "undefined") {
				res.set('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, COPY, HEAD, OPTIONS');
			}
			if (typeof req.get('Access-Control-Request-Headers') != "undefined") {
				res.set('Access-Control-Allow-Headers', req.get('Access-Control-Request-Headers'));
			}
			res.set('Access-Control-Max-Age', '86400');
			res.set('Access-Control-Allow-Credentials', 'true');
		}
		if (typeof req.get('Origin') != "undefined" ) {
			res.set('Access-Control-Allow-Origin', req.get('Origin'));
		}
		next();
	}
}

//---------------------------------------------------------------------------

function WafBlockConnection(req, res, ptrWafComp){
	res.Drop();
	wafutils.DisplayBlockedEvent({reason: ptrWafComp.Description, request: req, wafComp: ptrWafComp});
	wafutils.WriteEventToLog({reason: ptrWafComp.Description, request: req, wafComp: ptrWafComp}, 'BLOCK', (new Date().toLocaleDateString()).replace(/[\/\:]/ig, '-') + ' Events.log');
}

//---------------------------------------------------------------------------

function WafRegisterCallback(wafObj, lpCallback) {
	let guid = uuid();
	let flag = true;
	while (flag){
		flag = false;
		for (let idx = 0; idx < wafObj.Callbacks.length; idx++){
			if (wafObj.Callbacks[idx].Guid == guid){
				flag = true;
				guid = uuid();
			}
		}
	}
	wafObj.Callbacks.push({ Callback: lpCallback, Guid: guid });
	return guid;
}

function WafUnregisterCallback(wafObj, callbackUuid) {
	let status = false;
	for (let idx = 0; idx < wafObj.Callbacks.length; idx++){
		if (wafObj.Callbacks[idx].Guid == callbackUuid){
			wafObj.Callbacks.splice(idx, 1);
			status = true;
			break;
		}
	}
	return status;
}

//---------------------------------------------------------------------------

function WafCheckFlags(value, flag) {
	return ((value & flag) === flag);
}

function WafTranslateAssertions(matchList) {
	if (typeof matchList !== "undefined" && matchList !== null) {
		let assertions = [];
		for (let k = 0; k < matchList.length; k++) {
			if (matchList[k].Flag == true) {
				assertions.push(matchList[k].Match);
			}
		}
		return assertions;
	}
	else {
		return [];
	}
}

function WafCheckAssertions(asserts, boolOp, bDenyAsserts) {
	let result = (bDenyAsserts ? !asserts[0] : asserts[0]);
	for (let k = 1; k < asserts.length; k++) {
		result = (bDenyAsserts ? (boolOp == WAF_ASSERTION_OPERATOR.OP_OR ? result || !asserts[k] : (boolOp == WAF_ASSERTION_OPERATOR.OP_AND ? result = result && !asserts[k] : false)) : (boolOp == WAF_ASSERTION_OPERATOR.OP_OR ? result || asserts[k] : (boolOp == WAF_ASSERTION_OPERATOR.OP_AND ? result = result && asserts[k] : false)));
	}
	return result;
}

//---------------------------------------------------------------------------

module.exports = {

	//Enums of Mini WAF
	WAF_ASSERTION_OPERATOR: WAF_ASSERTION_OPERATOR,
	WAF_NETWORK_LAYER: WAF_NETWORK_LAYER,
	WAF_MATCH_TYPE: WAF_MATCH_TYPE,
	WAF_MANAGE_TYPE: WAF_MANAGE_TYPE,
	WAF_RULE_DIRECTION: WAF_RULE_DIRECTION,

	//Base functions of Mini WAF
	WafMiddleware: WafMiddleware,
	WafSecurityPolicy: WafSecurityPolicy,
	WafBlockConnection: WafBlockConnection,
	WafRegisterCallback: WafRegisterCallback,
	WafUnregisterCallback: WafUnregisterCallback,
	WafCheckFlags: WafCheckFlags,
	WafTranslateAssertions: WafTranslateAssertions,
	WafCheckAssertions: WafCheckAssertions

}